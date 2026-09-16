rule TTP_XOR_WriteProcessMemory_0397 {
  strings:
    $key_0397 = { 54 e5 [2] 66 c7 [2] 60 f2 [2] 4e f2 [2] 71 ee }

  condition:
    any of them
}