rule TTP_XOR_WriteProcessMemory_5af9 {
  strings:
    $key_5af9 = { 0d 8b [2] 3f a9 [2] 39 9c [2] 17 9c [2] 28 80 }

  condition:
    any of them
}