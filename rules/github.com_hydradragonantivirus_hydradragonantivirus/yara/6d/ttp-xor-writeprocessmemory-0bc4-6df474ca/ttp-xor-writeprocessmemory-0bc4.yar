rule TTP_XOR_WriteProcessMemory_0bc4 {
  strings:
    $key_0bc4 = { 5c b6 [2] 6e 94 [2] 68 a1 [2] 46 a1 [2] 79 bd }

  condition:
    any of them
}