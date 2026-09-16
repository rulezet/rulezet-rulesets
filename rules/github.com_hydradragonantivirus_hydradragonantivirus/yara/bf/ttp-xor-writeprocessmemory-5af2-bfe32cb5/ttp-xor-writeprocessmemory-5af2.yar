rule TTP_XOR_WriteProcessMemory_5af2 {
  strings:
    $key_5af2 = { 0d 80 [2] 3f a2 [2] 39 97 [2] 17 97 [2] 28 8b }

  condition:
    any of them
}