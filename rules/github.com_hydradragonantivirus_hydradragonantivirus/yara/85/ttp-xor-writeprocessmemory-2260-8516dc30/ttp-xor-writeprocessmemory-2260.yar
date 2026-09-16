rule TTP_XOR_WriteProcessMemory_2260 {
  strings:
    $key_2260 = { 75 12 [2] 47 30 [2] 41 05 [2] 6f 05 [2] 50 19 }

  condition:
    any of them
}