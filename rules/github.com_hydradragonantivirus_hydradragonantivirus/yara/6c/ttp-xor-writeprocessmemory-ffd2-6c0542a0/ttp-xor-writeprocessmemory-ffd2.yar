rule TTP_XOR_WriteProcessMemory_ffd2 {
  strings:
    $key_ffd2 = { a8 a0 [2] 9a 82 [2] 9c b7 [2] b2 b7 [2] 8d ab }

  condition:
    any of them
}