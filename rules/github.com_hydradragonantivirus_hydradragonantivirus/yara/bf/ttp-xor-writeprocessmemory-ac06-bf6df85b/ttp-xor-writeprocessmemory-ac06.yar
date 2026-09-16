rule TTP_XOR_WriteProcessMemory_ac06 {
  strings:
    $key_ac06 = { fb 74 [2] c9 56 [2] cf 63 [2] e1 63 [2] de 7f }

  condition:
    any of them
}