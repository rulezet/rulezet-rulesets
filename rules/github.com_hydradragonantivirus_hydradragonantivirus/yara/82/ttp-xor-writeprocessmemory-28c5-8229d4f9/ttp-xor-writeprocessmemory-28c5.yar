rule TTP_XOR_WriteProcessMemory_28c5 {
  strings:
    $key_28c5 = { 7f b7 [2] 4d 95 [2] 4b a0 [2] 65 a0 [2] 5a bc }

  condition:
    any of them
}