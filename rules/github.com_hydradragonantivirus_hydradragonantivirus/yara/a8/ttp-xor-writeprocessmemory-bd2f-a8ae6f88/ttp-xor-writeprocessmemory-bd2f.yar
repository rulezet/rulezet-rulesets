rule TTP_XOR_WriteProcessMemory_bd2f {
  strings:
    $key_bd2f = { ea 5d [2] d8 7f [2] de 4a [2] f0 4a [2] cf 56 }

  condition:
    any of them
}