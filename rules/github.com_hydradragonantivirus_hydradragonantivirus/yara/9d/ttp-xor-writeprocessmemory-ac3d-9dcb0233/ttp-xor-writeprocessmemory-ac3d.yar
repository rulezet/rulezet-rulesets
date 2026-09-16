rule TTP_XOR_WriteProcessMemory_ac3d {
  strings:
    $key_ac3d = { fb 4f [2] c9 6d [2] cf 58 [2] e1 58 [2] de 44 }

  condition:
    any of them
}