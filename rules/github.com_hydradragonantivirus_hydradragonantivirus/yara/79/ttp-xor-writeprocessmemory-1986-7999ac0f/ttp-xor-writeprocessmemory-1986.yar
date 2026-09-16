rule TTP_XOR_WriteProcessMemory_1986 {
  strings:
    $key_1986 = { 4e f4 [2] 7c d6 [2] 7a e3 [2] 54 e3 [2] 6b ff }

  condition:
    any of them
}