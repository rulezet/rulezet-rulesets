rule TTP_XOR_WriteProcessMemory_3ae2 {
  strings:
    $key_3ae2 = { 6d 90 [2] 5f b2 [2] 59 87 [2] 77 87 [2] 48 9b }

  condition:
    any of them
}