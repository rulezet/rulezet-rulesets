rule TTP_XOR_WriteProcessMemory_1617 {
  strings:
    $key_1617 = { 41 65 [2] 73 47 [2] 75 72 [2] 5b 72 [2] 64 6e }

  condition:
    any of them
}