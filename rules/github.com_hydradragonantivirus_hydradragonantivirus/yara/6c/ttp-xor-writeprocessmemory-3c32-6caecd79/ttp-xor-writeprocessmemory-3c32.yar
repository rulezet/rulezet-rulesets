rule TTP_XOR_WriteProcessMemory_3c32 {
  strings:
    $key_3c32 = { 6b 40 [2] 59 62 [2] 5f 57 [2] 71 57 [2] 4e 4b }

  condition:
    any of them
}