rule TTP_XOR_WriteProcessMemory_36e7 {
  strings:
    $key_36e7 = { 61 95 [2] 53 b7 [2] 55 82 [2] 7b 82 [2] 44 9e }

  condition:
    any of them
}