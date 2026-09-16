rule TTP_XOR_WriteProcessMemory_1358 {
  strings:
    $key_1358 = { 44 2a [2] 76 08 [2] 70 3d [2] 5e 3d [2] 61 21 }

  condition:
    any of them
}