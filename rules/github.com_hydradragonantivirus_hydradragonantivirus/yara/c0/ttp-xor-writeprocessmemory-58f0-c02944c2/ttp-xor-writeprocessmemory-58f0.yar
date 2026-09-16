rule TTP_XOR_WriteProcessMemory_58f0 {
  strings:
    $key_58f0 = { 0f 82 [2] 3d a0 [2] 3b 95 [2] 15 95 [2] 2a 89 }

  condition:
    any of them
}