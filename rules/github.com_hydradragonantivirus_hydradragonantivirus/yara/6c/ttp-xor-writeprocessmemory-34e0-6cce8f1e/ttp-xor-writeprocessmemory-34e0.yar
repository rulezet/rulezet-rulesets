rule TTP_XOR_WriteProcessMemory_34e0 {
  strings:
    $key_34e0 = { 63 92 [2] 51 b0 [2] 57 85 [2] 79 85 [2] 46 99 }

  condition:
    any of them
}