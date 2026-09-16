rule TTP_XOR_WriteProcessMemory_6086 {
  strings:
    $key_6086 = { 37 f4 [2] 05 d6 [2] 03 e3 [2] 2d e3 [2] 12 ff }

  condition:
    any of them
}