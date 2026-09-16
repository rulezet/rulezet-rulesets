rule TTP_XOR_WriteProcessMemory_28c0 {
  strings:
    $key_28c0 = { 7f b2 [2] 4d 90 [2] 4b a5 [2] 65 a5 [2] 5a b9 }

  condition:
    any of them
}