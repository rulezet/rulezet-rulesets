rule TTP_XOR_WriteProcessMemory_33d0 {
  strings:
    $key_33d0 = { 64 a2 [2] 56 80 [2] 50 b5 [2] 7e b5 [2] 41 a9 }

  condition:
    any of them
}