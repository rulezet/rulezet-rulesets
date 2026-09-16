rule TTP_XOR_WriteProcessMemory_ac6c {
  strings:
    $key_ac6c = { fb 1e [2] c9 3c [2] cf 09 [2] e1 09 [2] de 15 }

  condition:
    any of them
}