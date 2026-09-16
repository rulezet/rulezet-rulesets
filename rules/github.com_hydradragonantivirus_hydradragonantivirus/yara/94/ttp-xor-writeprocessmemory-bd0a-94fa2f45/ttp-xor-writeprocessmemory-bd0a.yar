rule TTP_XOR_WriteProcessMemory_bd0a {
  strings:
    $key_bd0a = { ea 78 [2] d8 5a [2] de 6f [2] f0 6f [2] cf 73 }

  condition:
    any of them
}