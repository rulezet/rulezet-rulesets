rule TTP_XOR_WriteProcessMemory_ac46 {
  strings:
    $key_ac46 = { fb 34 [2] c9 16 [2] cf 23 [2] e1 23 [2] de 3f }

  condition:
    any of them
}