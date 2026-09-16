rule TTP_XOR_WriteProcessMemory_0341 {
  strings:
    $key_0341 = { 54 33 [2] 66 11 [2] 60 24 [2] 4e 24 [2] 71 38 }

  condition:
    any of them
}