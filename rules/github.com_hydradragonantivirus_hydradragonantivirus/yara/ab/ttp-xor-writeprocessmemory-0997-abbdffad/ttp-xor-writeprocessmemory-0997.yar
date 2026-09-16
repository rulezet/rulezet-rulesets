rule TTP_XOR_WriteProcessMemory_0997 {
  strings:
    $key_0997 = { 5e e5 [2] 6c c7 [2] 6a f2 [2] 44 f2 [2] 7b ee }

  condition:
    any of them
}