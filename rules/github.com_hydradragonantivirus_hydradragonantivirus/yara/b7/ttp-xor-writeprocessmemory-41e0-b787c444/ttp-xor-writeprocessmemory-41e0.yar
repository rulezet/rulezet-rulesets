rule TTP_XOR_WriteProcessMemory_41e0 {
  strings:
    $key_41e0 = { 16 92 [2] 24 b0 [2] 22 85 [2] 0c 85 [2] 33 99 }

  condition:
    any of them
}