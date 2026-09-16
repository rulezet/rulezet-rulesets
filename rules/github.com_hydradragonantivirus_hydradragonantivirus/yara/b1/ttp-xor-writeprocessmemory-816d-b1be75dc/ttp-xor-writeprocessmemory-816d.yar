rule TTP_XOR_WriteProcessMemory_816d {
  strings:
    $key_816d = { d6 1f [2] e4 3d [2] e2 08 [2] cc 08 [2] f3 14 }

  condition:
    any of them
}