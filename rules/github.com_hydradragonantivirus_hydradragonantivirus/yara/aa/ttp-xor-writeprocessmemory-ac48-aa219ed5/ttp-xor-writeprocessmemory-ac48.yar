rule TTP_XOR_WriteProcessMemory_ac48 {
  strings:
    $key_ac48 = { fb 3a [2] c9 18 [2] cf 2d [2] e1 2d [2] de 31 }

  condition:
    any of them
}