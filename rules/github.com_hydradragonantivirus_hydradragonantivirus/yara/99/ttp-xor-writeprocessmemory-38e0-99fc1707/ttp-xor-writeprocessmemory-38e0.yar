rule TTP_XOR_WriteProcessMemory_38e0 {
  strings:
    $key_38e0 = { 6f 92 [2] 5d b0 [2] 5b 85 [2] 75 85 [2] 4a 99 }

  condition:
    any of them
}