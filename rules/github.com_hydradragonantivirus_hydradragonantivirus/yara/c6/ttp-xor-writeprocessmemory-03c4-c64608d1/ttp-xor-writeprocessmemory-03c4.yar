rule TTP_XOR_WriteProcessMemory_03c4 {
  strings:
    $key_03c4 = { 54 b6 [2] 66 94 [2] 60 a1 [2] 4e a1 [2] 71 bd }

  condition:
    any of them
}