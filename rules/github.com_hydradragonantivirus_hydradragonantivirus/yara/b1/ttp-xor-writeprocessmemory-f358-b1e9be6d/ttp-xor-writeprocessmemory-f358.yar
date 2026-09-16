rule TTP_XOR_WriteProcessMemory_f358 {
  strings:
    $key_f358 = { a4 2a [2] 96 08 [2] 90 3d [2] be 3d [2] 81 21 }

  condition:
    any of them
}