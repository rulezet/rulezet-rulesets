rule TTP_XOR_WriteProcessMemory_bd7a {
  strings:
    $key_bd7a = { ea 08 [2] d8 2a [2] de 1f [2] f0 1f [2] cf 03 }

  condition:
    any of them
}