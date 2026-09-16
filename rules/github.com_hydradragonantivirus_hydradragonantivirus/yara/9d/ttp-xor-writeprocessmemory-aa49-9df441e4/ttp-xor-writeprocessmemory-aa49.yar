rule TTP_XOR_WriteProcessMemory_aa49 {
  strings:
    $key_aa49 = { fd 3b [2] cf 19 [2] c9 2c [2] e7 2c [2] d8 30 }

  condition:
    any of them
}