rule TTP_XOR_WriteProcessMemory_58e0 {
  strings:
    $key_58e0 = { 0f 92 [2] 3d b0 [2] 3b 85 [2] 15 85 [2] 2a 99 }

  condition:
    any of them
}