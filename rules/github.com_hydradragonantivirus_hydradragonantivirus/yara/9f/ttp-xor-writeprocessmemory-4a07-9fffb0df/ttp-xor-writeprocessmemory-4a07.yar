rule TTP_XOR_WriteProcessMemory_4a07 {
  strings:
    $key_4a07 = { 1d 75 [2] 2f 57 [2] 29 62 [2] 07 62 [2] 38 7e }

  condition:
    any of them
}