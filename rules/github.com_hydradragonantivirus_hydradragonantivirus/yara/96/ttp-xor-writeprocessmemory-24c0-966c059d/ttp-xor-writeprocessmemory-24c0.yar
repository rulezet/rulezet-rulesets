rule TTP_XOR_WriteProcessMemory_24c0 {
  strings:
    $key_24c0 = { 73 b2 [2] 41 90 [2] 47 a5 [2] 69 a5 [2] 56 b9 }

  condition:
    any of them
}