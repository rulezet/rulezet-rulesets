rule TTP_XOR_WriteProcessMemory_3086 {
  strings:
    $key_3086 = { 67 f4 [2] 55 d6 [2] 53 e3 [2] 7d e3 [2] 42 ff }

  condition:
    any of them
}