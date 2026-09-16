rule TTP_XOR_WriteProcessMemory_24d1 {
  strings:
    $key_24d1 = { 73 a3 [2] 41 81 [2] 47 b4 [2] 69 b4 [2] 56 a8 }

  condition:
    any of them
}