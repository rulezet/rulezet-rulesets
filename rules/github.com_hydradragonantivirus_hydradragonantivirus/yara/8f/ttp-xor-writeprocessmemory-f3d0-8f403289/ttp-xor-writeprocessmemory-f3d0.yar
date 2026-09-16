rule TTP_XOR_WriteProcessMemory_f3d0 {
  strings:
    $key_f3d0 = { a4 a2 [2] 96 80 [2] 90 b5 [2] be b5 [2] 81 a9 }

  condition:
    any of them
}