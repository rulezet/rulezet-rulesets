rule TTP_XOR_WriteProcessMemory_ac23 {
  strings:
    $key_ac23 = { fb 51 [2] c9 73 [2] cf 46 [2] e1 46 [2] de 5a }

  condition:
    any of them
}