rule TTP_XOR_WriteProcessMemory_ac25 {
  strings:
    $key_ac25 = { fb 57 [2] c9 75 [2] cf 40 [2] e1 40 [2] de 5c }

  condition:
    any of them
}