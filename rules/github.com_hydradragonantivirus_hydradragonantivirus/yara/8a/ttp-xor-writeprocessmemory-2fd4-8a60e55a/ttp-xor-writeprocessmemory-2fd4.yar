rule TTP_XOR_WriteProcessMemory_2fd4 {
  strings:
    $key_2fd4 = { 78 a6 [2] 4a 84 [2] 4c b1 [2] 62 b1 [2] 5d ad }

  condition:
    any of them
}