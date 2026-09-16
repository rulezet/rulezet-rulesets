rule TTP_XOR_WriteProcessMemory_ac76 {
  strings:
    $key_ac76 = { fb 04 [2] c9 26 [2] cf 13 [2] e1 13 [2] de 0f }

  condition:
    any of them
}