rule TTP_XOR_WriteProcessMemory_bd3a {
  strings:
    $key_bd3a = { ea 48 [2] d8 6a [2] de 5f [2] f0 5f [2] cf 43 }

  condition:
    any of them
}