rule TTP_XOR_WriteProcessMemory_aaf4 {
  strings:
    $key_aaf4 = { fd 86 [2] cf a4 [2] c9 91 [2] e7 91 [2] d8 8d }

  condition:
    any of them
}