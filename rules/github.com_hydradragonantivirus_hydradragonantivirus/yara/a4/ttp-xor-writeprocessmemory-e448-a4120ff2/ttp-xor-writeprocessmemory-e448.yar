rule TTP_XOR_WriteProcessMemory_e448 {
  strings:
    $key_e448 = { b3 3a [2] 81 18 [2] 87 2d [2] a9 2d [2] 96 31 }

  condition:
    any of them
}