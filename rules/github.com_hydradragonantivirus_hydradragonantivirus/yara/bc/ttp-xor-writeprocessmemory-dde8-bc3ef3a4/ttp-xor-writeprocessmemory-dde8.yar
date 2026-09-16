rule TTP_XOR_WriteProcessMemory_dde8 {
  strings:
    $key_dde8 = { 8a 9a [2] b8 b8 [2] be 8d [2] 90 8d [2] af 91 }

  condition:
    any of them
}