rule TTP_XOR_WriteProcessMemory_1bc4 {
  strings:
    $key_1bc4 = { 4c b6 [2] 7e 94 [2] 78 a1 [2] 56 a1 [2] 69 bd }

  condition:
    any of them
}