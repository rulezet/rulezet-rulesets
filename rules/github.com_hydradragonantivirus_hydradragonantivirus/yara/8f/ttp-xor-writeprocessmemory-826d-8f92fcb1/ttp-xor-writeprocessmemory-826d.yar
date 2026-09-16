rule TTP_XOR_WriteProcessMemory_826d {
  strings:
    $key_826d = { d5 1f [2] e7 3d [2] e1 08 [2] cf 08 [2] f0 14 }

  condition:
    any of them
}