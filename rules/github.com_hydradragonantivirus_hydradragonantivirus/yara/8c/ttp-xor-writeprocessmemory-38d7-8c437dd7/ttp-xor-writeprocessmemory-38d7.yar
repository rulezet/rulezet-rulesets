rule TTP_XOR_WriteProcessMemory_38d7 {
  strings:
    $key_38d7 = { 6f a5 [2] 5d 87 [2] 5b b2 [2] 75 b2 [2] 4a ae }

  condition:
    any of them
}