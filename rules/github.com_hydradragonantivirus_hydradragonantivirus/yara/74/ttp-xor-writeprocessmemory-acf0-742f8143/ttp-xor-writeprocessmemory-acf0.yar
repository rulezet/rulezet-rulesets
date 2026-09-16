rule TTP_XOR_WriteProcessMemory_acf0 {
  strings:
    $key_acf0 = { fb 82 [2] c9 a0 [2] cf 95 [2] e1 95 [2] de 89 }

  condition:
    any of them
}