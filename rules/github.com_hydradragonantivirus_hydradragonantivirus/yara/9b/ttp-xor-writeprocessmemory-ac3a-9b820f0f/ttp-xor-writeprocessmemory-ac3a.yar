rule TTP_XOR_WriteProcessMemory_ac3a {
  strings:
    $key_ac3a = { fb 48 [2] c9 6a [2] cf 5f [2] e1 5f [2] de 43 }

  condition:
    any of them
}