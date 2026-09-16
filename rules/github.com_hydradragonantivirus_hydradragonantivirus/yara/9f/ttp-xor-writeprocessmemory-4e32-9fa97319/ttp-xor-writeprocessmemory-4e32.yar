rule TTP_XOR_WriteProcessMemory_4e32 {
  strings:
    $key_4e32 = { 19 40 [2] 2b 62 [2] 2d 57 [2] 03 57 [2] 3c 4b }

  condition:
    any of them
}