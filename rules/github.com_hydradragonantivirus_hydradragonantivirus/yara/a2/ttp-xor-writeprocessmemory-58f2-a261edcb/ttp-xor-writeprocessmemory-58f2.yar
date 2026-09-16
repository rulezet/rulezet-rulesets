rule TTP_XOR_WriteProcessMemory_58f2 {
  strings:
    $key_58f2 = { 0f 80 [2] 3d a2 [2] 3b 97 [2] 15 97 [2] 2a 8b }

  condition:
    any of them
}