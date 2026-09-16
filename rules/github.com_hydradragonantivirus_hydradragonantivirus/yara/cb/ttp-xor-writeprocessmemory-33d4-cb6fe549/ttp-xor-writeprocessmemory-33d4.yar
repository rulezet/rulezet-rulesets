rule TTP_XOR_WriteProcessMemory_33d4 {
  strings:
    $key_33d4 = { 64 a6 [2] 56 84 [2] 50 b1 [2] 7e b1 [2] 41 ad }

  condition:
    any of them
}