rule TTP_XOR_WriteProcessMemory_aa6e {
  strings:
    $key_aa6e = { fd 1c [2] cf 3e [2] c9 0b [2] e7 0b [2] d8 17 }

  condition:
    any of them
}