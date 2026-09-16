rule TTP_XOR_WriteProcessMemory_3d80 {
  strings:
    $key_3d80 = { 6a f2 [2] 58 d0 [2] 5e e5 [2] 70 e5 [2] 4f f9 }

  condition:
    any of them
}