rule TTP_XOR_WriteProcessMemory_6986 {
  strings:
    $key_6986 = { 3e f4 [2] 0c d6 [2] 0a e3 [2] 24 e3 [2] 1b ff }

  condition:
    any of them
}