rule TTP_XOR_WriteProcessMemory_f758 {
  strings:
    $key_f758 = { a0 2a [2] 92 08 [2] 94 3d [2] ba 3d [2] 85 21 }

  condition:
    any of them
}