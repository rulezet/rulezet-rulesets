rule TTP_XOR_WriteProcessMemory_0353 {
  strings:
    $key_0353 = { 54 21 [2] 66 03 [2] 60 36 [2] 4e 36 [2] 71 2a }

  condition:
    any of them
}