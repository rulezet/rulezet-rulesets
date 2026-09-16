rule TTP_XOR_WriteProcessMemory_ffd4 {
  strings:
    $key_ffd4 = { a8 a6 [2] 9a 84 [2] 9c b1 [2] b2 b1 [2] 8d ad }

  condition:
    any of them
}