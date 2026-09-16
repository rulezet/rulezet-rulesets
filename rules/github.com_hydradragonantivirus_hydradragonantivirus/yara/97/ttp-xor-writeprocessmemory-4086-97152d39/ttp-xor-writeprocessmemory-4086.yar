rule TTP_XOR_WriteProcessMemory_4086 {
  strings:
    $key_4086 = { 17 f4 [2] 25 d6 [2] 23 e3 [2] 0d e3 [2] 32 ff }

  condition:
    any of them
}