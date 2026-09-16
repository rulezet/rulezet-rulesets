rule TTP_XOR_WriteProcessMemory_8358 {
  strings:
    $key_8358 = { d4 2a [2] e6 08 [2] e0 3d [2] ce 3d [2] f1 21 }

  condition:
    any of them
}