rule TTP_XOR_WriteProcessMemory_24d0 {
  strings:
    $key_24d0 = { 73 a2 [2] 41 80 [2] 47 b5 [2] 69 b5 [2] 56 a9 }

  condition:
    any of them
}