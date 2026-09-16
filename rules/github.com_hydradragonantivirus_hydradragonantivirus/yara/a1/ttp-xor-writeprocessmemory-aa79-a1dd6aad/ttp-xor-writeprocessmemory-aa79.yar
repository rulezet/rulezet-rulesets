rule TTP_XOR_WriteProcessMemory_aa79 {
  strings:
    $key_aa79 = { fd 0b [2] cf 29 [2] c9 1c [2] e7 1c [2] d8 00 }

  condition:
    any of them
}