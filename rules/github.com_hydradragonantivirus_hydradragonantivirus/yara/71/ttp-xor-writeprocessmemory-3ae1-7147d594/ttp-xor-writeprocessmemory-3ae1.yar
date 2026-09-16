rule TTP_XOR_WriteProcessMemory_3ae1 {
  strings:
    $key_3ae1 = { 6d 93 [2] 5f b1 [2] 59 84 [2] 77 84 [2] 48 98 }

  condition:
    any of them
}