rule TTP_XOR_WriteProcessMemory_ac52 {
  strings:
    $key_ac52 = { fb 20 [2] c9 02 [2] cf 37 [2] e1 37 [2] de 2b }

  condition:
    any of them
}