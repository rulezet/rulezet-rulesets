rule TTP_XOR_WriteProcessMemory_5a07 {
  strings:
    $key_5a07 = { 0d 75 [2] 3f 57 [2] 39 62 [2] 17 62 [2] 28 7e }

  condition:
    any of them
}