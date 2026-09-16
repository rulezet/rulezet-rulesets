rule TTP_XOR_WriteProcessMemory_78c5 {
  strings:
    $key_78c5 = { 2f b7 [2] 1d 95 [2] 1b a0 [2] 35 a0 [2] 0a bc }

  condition:
    any of them
}