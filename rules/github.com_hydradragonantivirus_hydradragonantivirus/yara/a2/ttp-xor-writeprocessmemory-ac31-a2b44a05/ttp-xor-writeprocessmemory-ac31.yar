rule TTP_XOR_WriteProcessMemory_ac31 {
  strings:
    $key_ac31 = { fb 43 [2] c9 61 [2] cf 54 [2] e1 54 [2] de 48 }

  condition:
    any of them
}