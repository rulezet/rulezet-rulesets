rule TTP_XOR_WriteProcessMemory_7ce7 {
  strings:
    $key_7ce7 = { 2b 95 [2] 19 b7 [2] 1f 82 [2] 31 82 [2] 0e 9e }

  condition:
    any of them
}