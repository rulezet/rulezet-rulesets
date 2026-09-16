rule TTP_XOR_WriteProcessMemory_56d6 {
  strings:
    $key_56d6 = { 01 a4 [2] 33 86 [2] 35 b3 [2] 1b b3 [2] 24 af }

  condition:
    any of them
}