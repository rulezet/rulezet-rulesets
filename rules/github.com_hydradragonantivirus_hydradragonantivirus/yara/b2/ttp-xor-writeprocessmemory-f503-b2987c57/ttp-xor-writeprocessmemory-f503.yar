rule TTP_XOR_WriteProcessMemory_f503 {
  strings:
    $key_f503 = { a2 71 [2] 90 53 [2] 96 66 [2] b8 66 [2] 87 7a }

  condition:
    any of them
}