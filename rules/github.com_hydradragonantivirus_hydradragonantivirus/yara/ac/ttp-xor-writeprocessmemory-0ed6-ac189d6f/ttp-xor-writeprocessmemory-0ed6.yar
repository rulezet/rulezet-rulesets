rule TTP_XOR_WriteProcessMemory_0ed6 {
  strings:
    $key_0ed6 = { 59 a4 [2] 6b 86 [2] 6d b3 [2] 43 b3 [2] 7c af }

  condition:
    any of them
}