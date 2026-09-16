rule TTP_XOR_WriteProcessMemory_aa2a {
  strings:
    $key_aa2a = { fd 58 [2] cf 7a [2] c9 4f [2] e7 4f [2] d8 53 }

  condition:
    any of them
}