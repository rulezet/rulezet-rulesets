rule TTP_XOR_WriteProcessMemory_0503 {
  strings:
    $key_0503 = { 52 71 [2] 60 53 [2] 66 66 [2] 48 66 [2] 77 7a }

  condition:
    any of them
}