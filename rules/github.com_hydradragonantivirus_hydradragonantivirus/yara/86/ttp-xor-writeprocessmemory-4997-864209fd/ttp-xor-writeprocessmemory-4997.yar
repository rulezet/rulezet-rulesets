rule TTP_XOR_WriteProcessMemory_4997 {
  strings:
    $key_4997 = { 1e e5 [2] 2c c7 [2] 2a f2 [2] 04 f2 [2] 3b ee }

  condition:
    any of them
}