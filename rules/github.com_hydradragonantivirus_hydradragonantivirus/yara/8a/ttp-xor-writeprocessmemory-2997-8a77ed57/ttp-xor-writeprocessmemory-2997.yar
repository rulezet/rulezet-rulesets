rule TTP_XOR_WriteProcessMemory_2997 {
  strings:
    $key_2997 = { 7e e5 [2] 4c c7 [2] 4a f2 [2] 64 f2 [2] 5b ee }

  condition:
    any of them
}