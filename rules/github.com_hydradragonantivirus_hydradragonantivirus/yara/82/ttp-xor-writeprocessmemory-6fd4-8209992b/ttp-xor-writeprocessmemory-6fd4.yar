rule TTP_XOR_WriteProcessMemory_6fd4 {
  strings:
    $key_6fd4 = { 38 a6 [2] 0a 84 [2] 0c b1 [2] 22 b1 [2] 1d ad }

  condition:
    any of them
}