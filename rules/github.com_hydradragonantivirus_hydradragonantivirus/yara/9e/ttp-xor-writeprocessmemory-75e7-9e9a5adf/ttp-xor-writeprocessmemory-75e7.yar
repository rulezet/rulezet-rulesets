rule TTP_XOR_WriteProcessMemory_75e7 {
  strings:
    $key_75e7 = { 22 95 [2] 10 b7 [2] 16 82 [2] 38 82 [2] 07 9e }

  condition:
    any of them
}