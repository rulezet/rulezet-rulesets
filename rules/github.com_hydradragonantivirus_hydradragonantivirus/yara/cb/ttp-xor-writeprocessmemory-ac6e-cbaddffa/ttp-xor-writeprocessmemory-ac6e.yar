rule TTP_XOR_WriteProcessMemory_ac6e {
  strings:
    $key_ac6e = { fb 1c [2] c9 3e [2] cf 0b [2] e1 0b [2] de 17 }

  condition:
    any of them
}