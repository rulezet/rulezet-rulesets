rule TTP_XOR_WriteProcessMemory_2fe7 {
  strings:
    $key_2fe7 = { 78 95 [2] 4a b7 [2] 4c 82 [2] 62 82 [2] 5d 9e }

  condition:
    any of them
}