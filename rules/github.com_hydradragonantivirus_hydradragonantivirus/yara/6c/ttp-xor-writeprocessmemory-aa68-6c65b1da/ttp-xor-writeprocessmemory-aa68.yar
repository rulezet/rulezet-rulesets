rule TTP_XOR_WriteProcessMemory_aa68 {
  strings:
    $key_aa68 = { fd 1a [2] cf 38 [2] c9 0d [2] e7 0d [2] d8 11 }

  condition:
    any of them
}