rule TTP_XOR_WriteProcessMemory_2277 {
  strings:
    $key_2277 = { 75 05 [2] 47 27 [2] 41 12 [2] 6f 12 [2] 50 0e }

  condition:
    any of them
}