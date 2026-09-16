rule TTP_XOR_WriteProcessMemory_ac4a {
  strings:
    $key_ac4a = { fb 38 [2] c9 1a [2] cf 2f [2] e1 2f [2] de 33 }

  condition:
    any of them
}