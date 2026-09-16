rule TTP_XOR_WriteProcessMemory_2c84 {
  strings:
    $key_2c84 = { 7b f6 [2] 49 d4 [2] 4f e1 [2] 61 e1 [2] 5e fd }

  condition:
    any of them
}