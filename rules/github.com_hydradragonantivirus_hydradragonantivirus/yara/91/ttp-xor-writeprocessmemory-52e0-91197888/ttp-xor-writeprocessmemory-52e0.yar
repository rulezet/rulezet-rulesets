rule TTP_XOR_WriteProcessMemory_52e0 {
  strings:
    $key_52e0 = { 05 92 [2] 37 b0 [2] 31 85 [2] 1f 85 [2] 20 99 }

  condition:
    any of them
}