rule TTP_XOR_WriteProcessMemory_2477 {
  strings:
    $key_2477 = { 73 05 [2] 41 27 [2] 47 12 [2] 69 12 [2] 56 0e }

  condition:
    any of them
}