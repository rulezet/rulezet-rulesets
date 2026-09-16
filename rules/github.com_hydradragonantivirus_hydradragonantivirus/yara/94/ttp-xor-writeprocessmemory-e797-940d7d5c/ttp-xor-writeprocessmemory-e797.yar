rule TTP_XOR_WriteProcessMemory_e797 {
  strings:
    $key_e797 = { b0 e5 [2] 82 c7 [2] 84 f2 [2] aa f2 [2] 95 ee }

  condition:
    any of them
}