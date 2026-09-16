rule TTP_XOR_WriteProcessMemory_0e32 {
  strings:
    $key_0e32 = { 59 40 [2] 6b 62 [2] 6d 57 [2] 43 57 [2] 7c 4b }

  condition:
    any of them
}