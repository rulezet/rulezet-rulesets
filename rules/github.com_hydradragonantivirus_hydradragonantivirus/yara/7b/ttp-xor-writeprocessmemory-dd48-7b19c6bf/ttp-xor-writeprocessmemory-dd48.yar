rule TTP_XOR_WriteProcessMemory_dd48 {
  strings:
    $key_dd48 = { 8a 3a [2] b8 18 [2] be 2d [2] 90 2d [2] af 31 }

  condition:
    any of them
}