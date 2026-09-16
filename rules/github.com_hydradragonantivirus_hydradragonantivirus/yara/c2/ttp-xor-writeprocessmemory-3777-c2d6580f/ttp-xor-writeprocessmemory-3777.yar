rule TTP_XOR_WriteProcessMemory_3777 {
  strings:
    $key_3777 = { 60 05 [2] 52 27 [2] 54 12 [2] 7a 12 [2] 45 0e }

  condition:
    any of them
}