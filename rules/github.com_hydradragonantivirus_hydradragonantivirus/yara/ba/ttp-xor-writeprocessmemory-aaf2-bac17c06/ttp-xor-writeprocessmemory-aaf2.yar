rule TTP_XOR_WriteProcessMemory_aaf2 {
  strings:
    $key_aaf2 = { fd 80 [2] cf a2 [2] c9 97 [2] e7 97 [2] d8 8b }

  condition:
    any of them
}