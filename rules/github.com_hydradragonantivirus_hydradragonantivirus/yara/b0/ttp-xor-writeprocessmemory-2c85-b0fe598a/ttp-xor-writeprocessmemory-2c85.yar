rule TTP_XOR_WriteProcessMemory_2c85 {
  strings:
    $key_2c85 = { 7b f7 [2] 49 d5 [2] 4f e0 [2] 61 e0 [2] 5e fc }

  condition:
    any of them
}