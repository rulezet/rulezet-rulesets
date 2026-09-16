rule TTP_XOR_WriteProcessMemory_ac79 {
  strings:
    $key_ac79 = { fb 0b [2] c9 29 [2] cf 1c [2] e1 1c [2] de 00 }

  condition:
    any of them
}