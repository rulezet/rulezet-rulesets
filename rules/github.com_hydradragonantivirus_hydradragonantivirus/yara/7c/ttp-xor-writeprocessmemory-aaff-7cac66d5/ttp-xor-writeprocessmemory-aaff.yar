rule TTP_XOR_WriteProcessMemory_aaff {
  strings:
    $key_aaff = { fd 8d [2] cf af [2] c9 9a [2] e7 9a [2] d8 86 }

  condition:
    any of them
}