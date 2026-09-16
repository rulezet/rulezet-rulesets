rule TTP_XOR_WriteProcessMemory_8148 {
  strings:
    $key_8148 = { d6 3a [2] e4 18 [2] e2 2d [2] cc 2d [2] f3 31 }

  condition:
    any of them
}