rule TTP_XOR_WriteProcessMemory_6997 {
  strings:
    $key_6997 = { 3e e5 [2] 0c c7 [2] 0a f2 [2] 24 f2 [2] 1b ee }

  condition:
    any of them
}