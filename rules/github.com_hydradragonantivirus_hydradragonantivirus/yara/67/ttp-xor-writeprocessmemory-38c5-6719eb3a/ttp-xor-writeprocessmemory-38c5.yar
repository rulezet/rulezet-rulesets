rule TTP_XOR_WriteProcessMemory_38c5 {
  strings:
    $key_38c5 = { 6f b7 [2] 5d 95 [2] 5b a0 [2] 75 a0 [2] 4a bc }

  condition:
    any of them
}