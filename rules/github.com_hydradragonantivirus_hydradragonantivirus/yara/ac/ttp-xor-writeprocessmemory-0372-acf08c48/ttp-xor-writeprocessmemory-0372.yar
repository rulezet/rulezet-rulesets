rule TTP_XOR_WriteProcessMemory_0372 {
  strings:
    $key_0372 = { 54 00 [2] 66 22 [2] 60 17 [2] 4e 17 [2] 71 0b }

  condition:
    any of them
}