rule TTP_XOR_WriteProcessMemory_1997 {
  strings:
    $key_1997 = { 4e e5 [2] 7c c7 [2] 7a f2 [2] 54 f2 [2] 6b ee }

  condition:
    any of them
}