rule TTP_XOR_WriteProcessMemory_ac30 {
  strings:
    $key_ac30 = { fb 42 [2] c9 60 [2] cf 55 [2] e1 55 [2] de 49 }

  condition:
    any of them
}