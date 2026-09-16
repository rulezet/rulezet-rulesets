rule TTP_XOR_WriteProcessMemory_2086 {
  strings:
    $key_2086 = { 77 f4 [2] 45 d6 [2] 43 e3 [2] 6d e3 [2] 52 ff }

  condition:
    any of them
}