rule TTP_XOR_WriteProcessMemory_1bc1 {
  strings:
    $key_1bc1 = { 4c b3 [2] 7e 91 [2] 78 a4 [2] 56 a4 [2] 69 b8 }

  condition:
    any of them
}