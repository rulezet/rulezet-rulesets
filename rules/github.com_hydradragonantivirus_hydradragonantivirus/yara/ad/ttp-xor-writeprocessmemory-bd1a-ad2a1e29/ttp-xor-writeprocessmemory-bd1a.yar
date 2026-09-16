rule TTP_XOR_WriteProcessMemory_bd1a {
  strings:
    $key_bd1a = { ea 68 [2] d8 4a [2] de 7f [2] f0 7f [2] cf 63 }

  condition:
    any of them
}