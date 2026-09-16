rule TTP_XOR_WriteProcessMemory_0302 {
  strings:
    $key_0302 = { 54 70 [2] 66 52 [2] 60 67 [2] 4e 67 [2] 71 7b }

  condition:
    any of them
}