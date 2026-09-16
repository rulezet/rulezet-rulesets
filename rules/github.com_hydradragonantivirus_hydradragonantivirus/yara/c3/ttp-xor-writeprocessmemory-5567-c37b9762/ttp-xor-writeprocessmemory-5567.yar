rule TTP_XOR_WriteProcessMemory_5567 {
  strings:
    $key_5567 = { 02 15 [2] 30 37 [2] 36 02 [2] 18 02 [2] 27 1e }

  condition:
    any of them
}