rule TTP_XOR_WriteProcessMemory_dde3 {
  strings:
    $key_dde3 = { 8a 91 [2] b8 b3 [2] be 86 [2] 90 86 [2] af 9a }

  condition:
    any of them
}