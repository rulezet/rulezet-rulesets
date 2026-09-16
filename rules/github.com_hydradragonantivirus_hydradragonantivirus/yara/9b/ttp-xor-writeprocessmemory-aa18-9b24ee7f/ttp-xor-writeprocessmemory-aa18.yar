rule TTP_XOR_WriteProcessMemory_aa18 {
  strings:
    $key_aa18 = { fd 6a [2] cf 48 [2] c9 7d [2] e7 7d [2] d8 61 }

  condition:
    any of them
}