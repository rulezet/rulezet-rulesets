rule TTP_XOR_WriteProcessMemory_ac94 {
  strings:
    $key_ac94 = { fb e6 [2] c9 c4 [2] cf f1 [2] e1 f1 [2] de ed }

  condition:
    any of them
}