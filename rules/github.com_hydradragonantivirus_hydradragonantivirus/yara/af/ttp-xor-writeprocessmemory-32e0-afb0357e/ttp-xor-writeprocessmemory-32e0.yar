rule TTP_XOR_WriteProcessMemory_32e0 {
  strings:
    $key_32e0 = { 65 92 [2] 57 b0 [2] 51 85 [2] 7f 85 [2] 40 99 }

  condition:
    any of them
}