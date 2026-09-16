rule TTP_XOR_WriteProcessMemory_f3d9 {
  strings:
    $key_f3d9 = { a4 ab [2] 96 89 [2] 90 bc [2] be bc [2] 81 a0 }

  condition:
    any of them
}