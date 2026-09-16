rule TTP_XOR_WriteProcessMemory_ac00 {
  strings:
    $key_ac00 = { fb 72 [2] c9 50 [2] cf 65 [2] e1 65 [2] de 79 }

  condition:
    any of them
}