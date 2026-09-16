rule TTP_XOR_WriteProcessMemory_ac58 {
  strings:
    $key_ac58 = { fb 2a [2] c9 08 [2] cf 3d [2] e1 3d [2] de 21 }

  condition:
    any of them
}