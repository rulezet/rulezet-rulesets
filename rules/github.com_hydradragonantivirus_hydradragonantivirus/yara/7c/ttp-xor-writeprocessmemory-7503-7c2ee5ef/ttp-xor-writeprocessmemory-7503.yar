rule TTP_XOR_WriteProcessMemory_7503 {
  strings:
    $key_7503 = { 22 71 [2] 10 53 [2] 16 66 [2] 38 66 [2] 07 7a }

  condition:
    any of them
}