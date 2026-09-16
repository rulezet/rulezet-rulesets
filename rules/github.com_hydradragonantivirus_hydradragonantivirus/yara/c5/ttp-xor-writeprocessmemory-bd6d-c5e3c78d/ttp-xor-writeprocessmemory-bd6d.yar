rule TTP_XOR_WriteProcessMemory_bd6d {
  strings:
    $key_bd6d = { ea 1f [2] d8 3d [2] de 08 [2] f0 08 [2] cf 14 }

  condition:
    any of them
}