rule TTP_XOR_WriteProcessMemory_ac04 {
  strings:
    $key_ac04 = { fb 76 [2] c9 54 [2] cf 61 [2] e1 61 [2] de 7d }

  condition:
    any of them
}