rule TTP_XOR_WriteProcessMemory_6797 {
  strings:
    $key_6797 = { 30 e5 [2] 02 c7 [2] 04 f2 [2] 2a f2 [2] 15 ee }

  condition:
    any of them
}