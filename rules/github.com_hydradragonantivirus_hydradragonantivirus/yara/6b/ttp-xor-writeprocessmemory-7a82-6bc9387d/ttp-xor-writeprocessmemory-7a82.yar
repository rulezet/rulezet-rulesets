rule TTP_XOR_WriteProcessMemory_7a82 {
  strings:
    $key_7a82 = { 2d f0 [2] 1f d2 [2] 19 e7 [2] 37 e7 [2] 08 fb }

  condition:
    any of them
}