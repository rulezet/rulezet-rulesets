rule TTP_XOR_WriteProcessMemory_7af9 {
  strings:
    $key_7af9 = { 2d 8b [2] 1f a9 [2] 19 9c [2] 37 9c [2] 08 80 }

  condition:
    any of them
}