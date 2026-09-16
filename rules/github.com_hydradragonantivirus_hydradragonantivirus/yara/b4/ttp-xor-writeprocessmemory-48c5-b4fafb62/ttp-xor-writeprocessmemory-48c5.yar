rule TTP_XOR_WriteProcessMemory_48c5 {
  strings:
    $key_48c5 = { 1f b7 [2] 2d 95 [2] 2b a0 [2] 05 a0 [2] 3a bc }

  condition:
    any of them
}