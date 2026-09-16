rule TTP_XOR_WriteProcessMemory_aa2f {
  strings:
    $key_aa2f = { fd 5d [2] cf 7f [2] c9 4a [2] e7 4a [2] d8 56 }

  condition:
    any of them
}