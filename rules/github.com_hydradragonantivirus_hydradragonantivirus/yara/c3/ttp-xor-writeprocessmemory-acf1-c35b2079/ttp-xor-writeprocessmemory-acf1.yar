rule TTP_XOR_WriteProcessMemory_acf1 {
  strings:
    $key_acf1 = { fb 83 [2] c9 a1 [2] cf 94 [2] e1 94 [2] de 88 }

  condition:
    any of them
}