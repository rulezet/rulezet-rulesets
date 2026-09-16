rule TTP_XOR_WriteProcessMemory_ac2b {
  strings:
    $key_ac2b = { fb 59 [2] c9 7b [2] cf 4e [2] e1 4e [2] de 52 }

  condition:
    any of them
}