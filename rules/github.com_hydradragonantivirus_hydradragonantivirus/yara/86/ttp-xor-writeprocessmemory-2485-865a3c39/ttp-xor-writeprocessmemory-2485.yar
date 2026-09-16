rule TTP_XOR_WriteProcessMemory_2485 {
  strings:
    $key_2485 = { 73 f7 [2] 41 d5 [2] 47 e0 [2] 69 e0 [2] 56 fc }

  condition:
    any of them
}