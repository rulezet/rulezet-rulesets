rule TTP_XOR_WriteProcessMemory_77dc {
  strings:
    $key_77dc = { 20 ae [2] 12 8c [2] 14 b9 [2] 3a b9 [2] 05 a5 }

  condition:
    any of them
}