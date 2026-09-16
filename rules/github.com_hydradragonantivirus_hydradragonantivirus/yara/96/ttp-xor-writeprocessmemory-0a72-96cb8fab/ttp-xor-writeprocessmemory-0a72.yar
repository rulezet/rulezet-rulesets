rule TTP_XOR_WriteProcessMemory_0a72 {
  strings:
    $key_0a72 = { 5d 00 [2] 6f 22 [2] 69 17 [2] 47 17 [2] 78 0b }

  condition:
    any of them
}