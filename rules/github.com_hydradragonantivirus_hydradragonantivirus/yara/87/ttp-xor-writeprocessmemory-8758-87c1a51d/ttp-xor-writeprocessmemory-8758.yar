rule TTP_XOR_WriteProcessMemory_8758 {
  strings:
    $key_8758 = { d0 2a [2] e2 08 [2] e4 3d [2] ca 3d [2] f5 21 }

  condition:
    any of them
}