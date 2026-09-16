rule TTP_XOR_WriteProcessMemory_bdff {
  strings:
    $key_bdff = { ea 8d [2] d8 af [2] de 9a [2] f0 9a [2] cf 86 }

  condition:
    any of them
}