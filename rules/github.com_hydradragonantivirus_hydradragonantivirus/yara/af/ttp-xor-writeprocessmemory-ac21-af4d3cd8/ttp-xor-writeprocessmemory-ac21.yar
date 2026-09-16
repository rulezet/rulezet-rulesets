rule TTP_XOR_WriteProcessMemory_ac21 {
  strings:
    $key_ac21 = { fb 53 [2] c9 71 [2] cf 44 [2] e1 44 [2] de 58 }

  condition:
    any of them
}