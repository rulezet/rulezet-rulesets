rule TTP_XOR_WriteProcessMemory_4ce7 {
  strings:
    $key_4ce7 = { 1b 95 [2] 29 b7 [2] 2f 82 [2] 01 82 [2] 3e 9e }

  condition:
    any of them
}