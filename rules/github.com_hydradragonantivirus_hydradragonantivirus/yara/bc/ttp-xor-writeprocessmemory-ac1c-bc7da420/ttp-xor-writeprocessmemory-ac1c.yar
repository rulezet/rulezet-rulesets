rule TTP_XOR_WriteProcessMemory_ac1c {
  strings:
    $key_ac1c = { fb 6e [2] c9 4c [2] cf 79 [2] e1 79 [2] de 65 }

  condition:
    any of them
}