rule TTP_XOR_WriteProcessMemory_0358 {
  strings:
    $key_0358 = { 54 2a [2] 66 08 [2] 60 3d [2] 4e 3d [2] 71 21 }

  condition:
    any of them
}