rule TTP_XOR_WriteProcessMemory_03e7 {
  strings:
    $key_03e7 = { 54 95 [2] 66 b7 [2] 60 82 [2] 4e 82 [2] 71 9e }

  condition:
    any of them
}