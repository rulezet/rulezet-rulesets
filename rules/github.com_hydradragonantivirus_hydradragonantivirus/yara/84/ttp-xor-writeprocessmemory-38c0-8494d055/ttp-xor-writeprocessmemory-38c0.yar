rule TTP_XOR_WriteProcessMemory_38c0 {
  strings:
    $key_38c0 = { 6f b2 [2] 5d 90 [2] 5b a5 [2] 75 a5 [2] 4a b9 }

  condition:
    any of them
}