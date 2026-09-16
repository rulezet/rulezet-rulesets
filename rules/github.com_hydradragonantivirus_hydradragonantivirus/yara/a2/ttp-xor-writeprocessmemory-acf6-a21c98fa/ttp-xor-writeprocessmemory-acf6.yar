rule TTP_XOR_WriteProcessMemory_acf6 {
  strings:
    $key_acf6 = { fb 84 [2] c9 a6 [2] cf 93 [2] e1 93 [2] de 8f }

  condition:
    any of them
}