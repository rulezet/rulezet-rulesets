rule TTP_XOR_WriteProcessMemory_21e7 {
  strings:
    $key_21e7 = { 76 95 [2] 44 b7 [2] 42 82 [2] 6c 82 [2] 53 9e }

  condition:
    any of them
}