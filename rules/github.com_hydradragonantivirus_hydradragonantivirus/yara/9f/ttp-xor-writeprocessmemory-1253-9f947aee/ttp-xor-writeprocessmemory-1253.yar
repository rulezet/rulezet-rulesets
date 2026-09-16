rule TTP_XOR_WriteProcessMemory_1253 {
  strings:
    $key_1253 = { 45 21 [2] 77 03 [2] 71 36 [2] 5f 36 [2] 60 2a }

  condition:
    any of them
}