rule TTP_XOR_WriteProcessMemory_28e0 {
  strings:
    $key_28e0 = { 7f 92 [2] 4d b0 [2] 4b 85 [2] 65 85 [2] 5a 99 }

  condition:
    any of them
}