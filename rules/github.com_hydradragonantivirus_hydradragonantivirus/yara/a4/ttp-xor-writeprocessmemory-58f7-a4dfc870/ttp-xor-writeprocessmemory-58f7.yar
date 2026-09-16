rule TTP_XOR_WriteProcessMemory_58f7 {
  strings:
    $key_58f7 = { 0f 85 [2] 3d a7 [2] 3b 92 [2] 15 92 [2] 2a 8e }

  condition:
    any of them
}