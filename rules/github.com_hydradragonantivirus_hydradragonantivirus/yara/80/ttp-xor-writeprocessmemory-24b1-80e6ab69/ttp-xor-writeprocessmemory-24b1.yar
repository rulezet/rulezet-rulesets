rule TTP_XOR_WriteProcessMemory_24b1 {
  strings:
    $key_24b1 = { 73 c3 [2] 41 e1 [2] 47 d4 [2] 69 d4 [2] 56 c8 }

  condition:
    any of them
}