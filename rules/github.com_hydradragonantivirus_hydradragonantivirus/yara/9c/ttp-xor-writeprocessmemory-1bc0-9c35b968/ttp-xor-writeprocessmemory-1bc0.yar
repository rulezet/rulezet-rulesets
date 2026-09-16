rule TTP_XOR_WriteProcessMemory_1bc0 {
  strings:
    $key_1bc0 = { 4c b2 [2] 7e 90 [2] 78 a5 [2] 56 a5 [2] 69 b9 }

  condition:
    any of them
}