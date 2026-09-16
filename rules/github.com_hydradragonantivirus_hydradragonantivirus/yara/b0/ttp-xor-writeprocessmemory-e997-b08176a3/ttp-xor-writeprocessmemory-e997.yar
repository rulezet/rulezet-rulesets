rule TTP_XOR_WriteProcessMemory_e997 {
  strings:
    $key_e997 = { be e5 [2] 8c c7 [2] 8a f2 [2] a4 f2 [2] 9b ee }

  condition:
    any of them
}