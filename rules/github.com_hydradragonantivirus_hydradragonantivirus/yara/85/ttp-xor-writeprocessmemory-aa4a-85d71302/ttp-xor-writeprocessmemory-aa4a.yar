rule TTP_XOR_WriteProcessMemory_aa4a {
  strings:
    $key_aa4a = { fd 38 [2] cf 1a [2] c9 2f [2] e7 2f [2] d8 33 }

  condition:
    any of them
}