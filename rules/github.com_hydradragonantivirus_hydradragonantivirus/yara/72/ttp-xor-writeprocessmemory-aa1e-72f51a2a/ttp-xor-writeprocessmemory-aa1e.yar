rule TTP_XOR_WriteProcessMemory_aa1e {
  strings:
    $key_aa1e = { fd 6c [2] cf 4e [2] c9 7b [2] e7 7b [2] d8 67 }

  condition:
    any of them
}