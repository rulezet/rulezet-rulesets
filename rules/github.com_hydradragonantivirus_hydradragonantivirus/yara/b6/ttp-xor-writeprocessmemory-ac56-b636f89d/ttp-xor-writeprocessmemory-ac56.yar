rule TTP_XOR_WriteProcessMemory_ac56 {
  strings:
    $key_ac56 = { fb 24 [2] c9 06 [2] cf 33 [2] e1 33 [2] de 2f }

  condition:
    any of them
}