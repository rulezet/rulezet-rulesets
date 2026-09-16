rule TTP_XOR_WriteProcessMemory_69e7 {
  strings:
    $key_69e7 = { 3e 95 [2] 0c b7 [2] 0a 82 [2] 24 82 [2] 1b 9e }

  condition:
    any of them
}