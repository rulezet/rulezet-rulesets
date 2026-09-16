rule TTP_XOR_WriteProcessMemory_bd1f {
  strings:
    $key_bd1f = { ea 6d [2] d8 4f [2] de 7a [2] f0 7a [2] cf 66 }

  condition:
    any of them
}