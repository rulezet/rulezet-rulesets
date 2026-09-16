rule TTP_XOR_WriteProcessMemory_16e7 {
  strings:
    $key_16e7 = { 41 95 [2] 73 b7 [2] 75 82 [2] 5b 82 [2] 64 9e }

  condition:
    any of them
}