rule TTP_XOR_WriteProcessMemory_aa3e {
  strings:
    $key_aa3e = { fd 4c [2] cf 6e [2] c9 5b [2] e7 5b [2] d8 47 }

  condition:
    any of them
}