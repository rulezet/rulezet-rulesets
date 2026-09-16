rule TTP_XOR_WriteProcessMemory_4bc1 {
  strings:
    $key_4bc1 = { 1c b3 [2] 2e 91 [2] 28 a4 [2] 06 a4 [2] 39 b8 }

  condition:
    any of them
}