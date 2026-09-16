rule TTP_XOR_WriteProcessMemory_aa78 {
  strings:
    $key_aa78 = { fd 0a [2] cf 28 [2] c9 1d [2] e7 1d [2] d8 01 }

  condition:
    any of them
}