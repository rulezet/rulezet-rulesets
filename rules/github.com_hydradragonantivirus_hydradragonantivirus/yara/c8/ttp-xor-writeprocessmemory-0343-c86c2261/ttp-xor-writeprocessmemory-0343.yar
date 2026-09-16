rule TTP_XOR_WriteProcessMemory_0343 {
  strings:
    $key_0343 = { 54 31 [2] 66 13 [2] 60 26 [2] 4e 26 [2] 71 3a }

  condition:
    any of them
}