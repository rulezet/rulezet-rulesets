rule TTP_XOR_WriteProcessMemory_1bc3 {
  strings:
    $key_1bc3 = { 4c b1 [2] 7e 93 [2] 78 a6 [2] 56 a6 [2] 69 ba }

  condition:
    any of them
}