rule TTP_XOR_WriteProcessMemory_aa7e {
  strings:
    $key_aa7e = { fd 0c [2] cf 2e [2] c9 1b [2] e7 1b [2] d8 07 }

  condition:
    any of them
}