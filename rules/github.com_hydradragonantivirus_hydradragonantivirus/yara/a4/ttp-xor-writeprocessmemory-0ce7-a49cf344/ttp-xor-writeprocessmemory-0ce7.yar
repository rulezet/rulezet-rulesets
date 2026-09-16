rule TTP_XOR_WriteProcessMemory_0ce7 {
  strings:
    $key_0ce7 = { 5b 95 [2] 69 b7 [2] 6f 82 [2] 41 82 [2] 7e 9e }

  condition:
    any of them
}