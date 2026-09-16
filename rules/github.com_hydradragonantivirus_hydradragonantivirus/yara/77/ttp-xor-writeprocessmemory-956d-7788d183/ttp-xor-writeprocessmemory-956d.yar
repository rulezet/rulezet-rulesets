rule TTP_XOR_WriteProcessMemory_956d {
  strings:
    $key_956d = { c2 1f [2] f0 3d [2] f6 08 [2] d8 08 [2] e7 14 }

  condition:
    any of them
}