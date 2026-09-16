rule TTP_XOR_WriteProcessMemory_2630 {
  strings:
    $key_2630 = { 71 42 [2] 43 60 [2] 45 55 [2] 6b 55 [2] 54 49 }

  condition:
    any of them
}