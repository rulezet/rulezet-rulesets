rule TTP_XOR_WriteProcessMemory_ac71 {
  strings:
    $key_ac71 = { fb 03 [2] c9 21 [2] cf 14 [2] e1 14 [2] de 08 }

  condition:
    any of them
}