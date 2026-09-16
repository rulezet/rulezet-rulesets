rule TTP_XOR_WriteProcessMemory_33d6 {
  strings:
    $key_33d6 = { 64 a4 [2] 56 86 [2] 50 b3 [2] 7e b3 [2] 41 af }

  condition:
    any of them
}