rule TTP_XOR_WriteProcessMemory_f3d5 {
  strings:
    $key_f3d5 = { a4 a7 [2] 96 85 [2] 90 b0 [2] be b0 [2] 81 ac }

  condition:
    any of them
}