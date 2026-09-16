rule TTP_XOR_WriteProcessMemory_4bc0 {
  strings:
    $key_4bc0 = { 1c b2 [2] 2e 90 [2] 28 a5 [2] 06 a5 [2] 39 b9 }

  condition:
    any of them
}