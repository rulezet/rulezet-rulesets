rule TTP_XOR_WriteProcessMemory_3ae6 {
  strings:
    $key_3ae6 = { 6d 94 [2] 5f b6 [2] 59 83 [2] 77 83 [2] 48 9f }

  condition:
    any of them
}