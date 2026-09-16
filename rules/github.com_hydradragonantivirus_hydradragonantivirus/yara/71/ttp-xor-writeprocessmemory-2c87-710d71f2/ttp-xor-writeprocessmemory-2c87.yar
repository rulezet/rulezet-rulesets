rule TTP_XOR_WriteProcessMemory_2c87 {
  strings:
    $key_2c87 = { 7b f5 [2] 49 d7 [2] 4f e2 [2] 61 e2 [2] 5e fe }

  condition:
    any of them
}