rule TTP_XOR_WriteProcessMemory_ac42 {
  strings:
    $key_ac42 = { fb 30 [2] c9 12 [2] cf 27 [2] e1 27 [2] de 3b }

  condition:
    any of them
}