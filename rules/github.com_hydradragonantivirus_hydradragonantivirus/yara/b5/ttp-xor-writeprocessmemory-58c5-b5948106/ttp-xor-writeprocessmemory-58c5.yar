rule TTP_XOR_WriteProcessMemory_58c5 {
  strings:
    $key_58c5 = { 0f b7 [2] 3d 95 [2] 3b a0 [2] 15 a0 [2] 2a bc }

  condition:
    any of them
}