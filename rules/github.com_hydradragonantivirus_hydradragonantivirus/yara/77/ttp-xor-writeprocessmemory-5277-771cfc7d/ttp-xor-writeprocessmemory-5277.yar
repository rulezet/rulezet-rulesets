rule TTP_XOR_WriteProcessMemory_5277 {
  strings:
    $key_5277 = { 05 05 [2] 37 27 [2] 31 12 [2] 1f 12 [2] 20 0e }

  condition:
    any of them
}