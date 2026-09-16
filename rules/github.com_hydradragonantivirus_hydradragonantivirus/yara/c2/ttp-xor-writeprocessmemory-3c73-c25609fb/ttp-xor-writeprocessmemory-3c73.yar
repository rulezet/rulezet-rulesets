rule TTP_XOR_WriteProcessMemory_3c73 {
  strings:
    $key_3c73 = { 6b 01 [2] 59 23 [2] 5f 16 [2] 71 16 [2] 4e 0a }

  condition:
    any of them
}