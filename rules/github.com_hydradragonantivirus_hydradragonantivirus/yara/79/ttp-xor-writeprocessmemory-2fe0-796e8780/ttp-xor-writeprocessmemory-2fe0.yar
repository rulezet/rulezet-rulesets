rule TTP_XOR_WriteProcessMemory_2fe0 {
  strings:
    $key_2fe0 = { 78 92 [2] 4a b0 [2] 4c 85 [2] 62 85 [2] 5d 99 }

  condition:
    any of them
}