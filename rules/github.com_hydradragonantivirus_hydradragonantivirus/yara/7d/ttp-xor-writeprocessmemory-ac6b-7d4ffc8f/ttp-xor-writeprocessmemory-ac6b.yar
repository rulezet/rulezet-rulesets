rule TTP_XOR_WriteProcessMemory_ac6b {
  strings:
    $key_ac6b = { fb 19 [2] c9 3b [2] cf 0e [2] e1 0e [2] de 12 }

  condition:
    any of them
}