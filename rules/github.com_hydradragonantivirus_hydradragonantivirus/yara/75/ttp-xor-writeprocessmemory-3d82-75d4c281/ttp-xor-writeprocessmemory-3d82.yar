rule TTP_XOR_WriteProcessMemory_3d82 {
  strings:
    $key_3d82 = { 6a f0 [2] 58 d2 [2] 5e e7 [2] 70 e7 [2] 4f fb }

  condition:
    any of them
}