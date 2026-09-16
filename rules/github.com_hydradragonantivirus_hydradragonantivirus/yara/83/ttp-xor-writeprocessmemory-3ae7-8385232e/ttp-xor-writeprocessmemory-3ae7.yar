rule TTP_XOR_WriteProcessMemory_3ae7 {
  strings:
    $key_3ae7 = { 6d 95 [2] 5f b7 [2] 59 82 [2] 77 82 [2] 48 9e }

  condition:
    any of them
}