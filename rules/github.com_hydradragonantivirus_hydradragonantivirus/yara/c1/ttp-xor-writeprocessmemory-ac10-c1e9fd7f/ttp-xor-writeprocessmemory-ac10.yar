rule TTP_XOR_WriteProcessMemory_ac10 {
  strings:
    $key_ac10 = { fb 62 [2] c9 40 [2] cf 75 [2] e1 75 [2] de 69 }

  condition:
    any of them
}