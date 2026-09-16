rule TTP_XOR_WriteProcessMemory_ac4d {
  strings:
    $key_ac4d = { fb 3f [2] c9 1d [2] cf 28 [2] e1 28 [2] de 34 }

  condition:
    any of them
}