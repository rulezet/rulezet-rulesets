rule TTP_XOR_WriteProcessMemory_ac2e {
  strings:
    $key_ac2e = { fb 5c [2] c9 7e [2] cf 4b [2] e1 4b [2] de 57 }

  condition:
    any of them
}