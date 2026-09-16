rule TTP_XOR_WriteProcessMemory_ac47 {
  strings:
    $key_ac47 = { fb 35 [2] c9 17 [2] cf 22 [2] e1 22 [2] de 3e }

  condition:
    any of them
}