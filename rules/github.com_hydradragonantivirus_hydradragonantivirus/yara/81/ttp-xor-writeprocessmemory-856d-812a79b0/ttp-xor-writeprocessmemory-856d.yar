rule TTP_XOR_WriteProcessMemory_856d {
  strings:
    $key_856d = { d2 1f [2] e0 3d [2] e6 08 [2] c8 08 [2] f7 14 }

  condition:
    any of them
}