rule TTP_XOR_WriteProcessMemory_acf8 {
  strings:
    $key_acf8 = { fb 8a [2] c9 a8 [2] cf 9d [2] e1 9d [2] de 81 }

  condition:
    any of them
}