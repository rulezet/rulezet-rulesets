rule TTP_XOR_WriteProcessMemory_3997 {
  strings:
    $key_3997 = { 6e e5 [2] 5c c7 [2] 5a f2 [2] 74 f2 [2] 4b ee }

  condition:
    any of them
}