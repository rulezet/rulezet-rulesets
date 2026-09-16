rule TTP_XOR_WriteProcessMemory_aa2d {
  strings:
    $key_aa2d = { fd 5f [2] cf 7d [2] c9 48 [2] e7 48 [2] d8 54 }

  condition:
    any of them
}