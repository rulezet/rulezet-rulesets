rule TTP_XOR_WriteProcessMemory_0345 {
  strings:
    $key_0345 = { 54 37 [2] 66 15 [2] 60 20 [2] 4e 20 [2] 71 3c }

  condition:
    any of them
}