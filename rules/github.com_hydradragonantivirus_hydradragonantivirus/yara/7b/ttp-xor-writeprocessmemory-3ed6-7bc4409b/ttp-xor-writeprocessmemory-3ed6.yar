rule TTP_XOR_WriteProcessMemory_3ed6 {
  strings:
    $key_3ed6 = { 69 a4 [2] 5b 86 [2] 5d b3 [2] 73 b3 [2] 4c af }

  condition:
    any of them
}