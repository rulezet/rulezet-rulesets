rule TTP_XOR_WriteProcessMemory_fab9 {
  strings:
    $key_fab9 = { ad cb [2] 9f e9 [2] 99 dc [2] b7 dc [2] 88 c0 }

  condition:
    any of them
}