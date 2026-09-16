rule TTP_XOR_WriteProcessMemory_2667 {
  strings:
    $key_2667 = { 71 15 [2] 43 37 [2] 45 02 [2] 6b 02 [2] 54 1e }

  condition:
    any of them
}