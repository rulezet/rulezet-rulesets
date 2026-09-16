rule TTP_XOR_WriteProcessMemory_ac17 {
  strings:
    $key_ac17 = { fb 65 [2] c9 47 [2] cf 72 [2] e1 72 [2] de 6e }

  condition:
    any of them
}