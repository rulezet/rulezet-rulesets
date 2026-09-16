rule TTP_XOR_WriteProcessMemory_ac67 {
  strings:
    $key_ac67 = { fb 15 [2] c9 37 [2] cf 02 [2] e1 02 [2] de 1e }

  condition:
    any of them
}