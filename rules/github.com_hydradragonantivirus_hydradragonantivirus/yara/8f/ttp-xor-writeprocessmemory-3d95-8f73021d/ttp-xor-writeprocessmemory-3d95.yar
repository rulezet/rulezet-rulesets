rule TTP_XOR_WriteProcessMemory_3d95 {
  strings:
    $key_3d95 = { 6a e7 [2] 58 c5 [2] 5e f0 [2] 70 f0 [2] 4f ec }

  condition:
    any of them
}