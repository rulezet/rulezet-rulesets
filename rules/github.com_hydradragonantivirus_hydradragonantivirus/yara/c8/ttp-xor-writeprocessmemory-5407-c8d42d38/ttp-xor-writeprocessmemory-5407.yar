rule TTP_XOR_WriteProcessMemory_5407 {
  strings:
    $key_5407 = { 03 75 [2] 31 57 [2] 37 62 [2] 19 62 [2] 26 7e }

  condition:
    any of them
}