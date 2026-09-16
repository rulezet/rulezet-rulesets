rule TTP_XOR_WriteProcessMemory_4fc5 {
  strings:
    $key_4fc5 = { 18 b7 [2] 2a 95 [2] 2c a0 [2] 02 a0 [2] 3d bc }

  condition:
    any of them
}