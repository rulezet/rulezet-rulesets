rule TTP_XOR_WriteProcessMemory_ac32 {
  strings:
    $key_ac32 = { fb 40 [2] c9 62 [2] cf 57 [2] e1 57 [2] de 4b }

  condition:
    any of them
}