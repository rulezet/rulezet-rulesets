rule TTP_XOR_WriteProcessMemory_5007 {
  strings:
    $key_5007 = { 07 75 [2] 35 57 [2] 33 62 [2] 1d 62 [2] 22 7e }

  condition:
    any of them
}