rule TTP_XOR_WriteProcessMemory_1fe7 {
  strings:
    $key_1fe7 = { 48 95 [2] 7a b7 [2] 7c 82 [2] 52 82 [2] 6d 9e }

  condition:
    any of them
}