rule TTP_XOR_WriteProcessMemory_24e0 {
  strings:
    $key_24e0 = { 73 92 [2] 41 b0 [2] 47 85 [2] 69 85 [2] 56 99 }

  condition:
    any of them
}