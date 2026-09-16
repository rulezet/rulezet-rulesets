rule TTP_XOR_WriteProcessMemory_4986 {
  strings:
    $key_4986 = { 1e f4 [2] 2c d6 [2] 2a e3 [2] 04 e3 [2] 3b ff }

  condition:
    any of them
}