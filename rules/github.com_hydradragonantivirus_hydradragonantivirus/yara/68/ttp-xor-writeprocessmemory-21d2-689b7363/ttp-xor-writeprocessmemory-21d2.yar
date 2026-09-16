rule TTP_XOR_WriteProcessMemory_21d2 {
  strings:
    $key_21d2 = { 76 a0 [2] 44 82 [2] 42 b7 [2] 6c b7 [2] 53 ab }

  condition:
    any of them
}