rule TTP_XOR_WriteProcessMemory_bd6a {
  strings:
    $key_bd6a = { ea 18 [2] d8 3a [2] de 0f [2] f0 0f [2] cf 13 }

  condition:
    any of them
}