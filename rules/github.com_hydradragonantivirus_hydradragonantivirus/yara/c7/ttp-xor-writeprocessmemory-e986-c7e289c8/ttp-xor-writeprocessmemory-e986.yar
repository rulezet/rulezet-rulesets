rule TTP_XOR_WriteProcessMemory_e986 {
  strings:
    $key_e986 = { be f4 [2] 8c d6 [2] 8a e3 [2] a4 e3 [2] 9b ff }

  condition:
    any of them
}