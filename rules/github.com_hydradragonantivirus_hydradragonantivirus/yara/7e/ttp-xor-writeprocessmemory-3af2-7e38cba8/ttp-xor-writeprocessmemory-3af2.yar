rule TTP_XOR_WriteProcessMemory_3af2 {
  strings:
    $key_3af2 = { 6d 80 [2] 5f a2 [2] 59 97 [2] 77 97 [2] 48 8b }

  condition:
    any of them
}