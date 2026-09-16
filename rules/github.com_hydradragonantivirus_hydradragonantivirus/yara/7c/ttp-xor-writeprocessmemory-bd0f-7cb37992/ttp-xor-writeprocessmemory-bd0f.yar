rule TTP_XOR_WriteProcessMemory_bd0f {
  strings:
    $key_bd0f = { ea 7d [2] d8 5f [2] de 6a [2] f0 6a [2] cf 76 }

  condition:
    any of them
}