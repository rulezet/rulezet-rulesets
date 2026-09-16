rule TTP_XOR_WriteProcessMemory_e458 {
  strings:
    $key_e458 = { b3 2a [2] 81 08 [2] 87 3d [2] a9 3d [2] 96 21 }

  condition:
    any of them
}