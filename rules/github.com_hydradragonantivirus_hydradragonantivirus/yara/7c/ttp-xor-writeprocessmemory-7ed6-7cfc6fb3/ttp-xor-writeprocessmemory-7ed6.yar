rule TTP_XOR_WriteProcessMemory_7ed6 {
  strings:
    $key_7ed6 = { 29 a4 [2] 1b 86 [2] 1d b3 [2] 33 b3 [2] 0c af }

  condition:
    any of them
}