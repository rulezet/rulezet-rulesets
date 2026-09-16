rule TTP_XOR_WriteProcessMemory_0361 {
  strings:
    $key_0361 = { 54 13 [2] 66 31 [2] 60 04 [2] 4e 04 [2] 71 18 }

  condition:
    any of them
}