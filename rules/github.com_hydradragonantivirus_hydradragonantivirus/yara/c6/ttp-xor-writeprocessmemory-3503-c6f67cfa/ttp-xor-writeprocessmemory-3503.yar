rule TTP_XOR_WriteProcessMemory_3503 {
  strings:
    $key_3503 = { 62 71 [2] 50 53 [2] 56 66 [2] 78 66 [2] 47 7a }

  condition:
    any of them
}