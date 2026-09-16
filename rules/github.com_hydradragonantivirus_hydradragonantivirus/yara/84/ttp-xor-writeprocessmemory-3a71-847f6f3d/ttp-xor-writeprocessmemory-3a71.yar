rule TTP_XOR_WriteProcessMemory_3a71 {
  strings:
    $key_3a71 = { 6d 03 [2] 5f 21 [2] 59 14 [2] 77 14 [2] 48 08 }

  condition:
    any of them
}