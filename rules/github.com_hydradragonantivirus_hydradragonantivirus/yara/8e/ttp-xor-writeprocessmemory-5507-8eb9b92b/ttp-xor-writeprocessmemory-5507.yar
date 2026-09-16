rule TTP_XOR_WriteProcessMemory_5507 {
  strings:
    $key_5507 = { 02 75 [2] 30 57 [2] 36 62 [2] 18 62 [2] 27 7e }

  condition:
    any of them
}