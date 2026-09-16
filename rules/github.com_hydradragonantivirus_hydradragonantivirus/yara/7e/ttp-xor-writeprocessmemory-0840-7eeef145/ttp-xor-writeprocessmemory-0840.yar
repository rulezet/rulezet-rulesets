rule TTP_XOR_WriteProcessMemory_0840 {
  strings:
    $key_0840 = { 5f 32 [2] 6d 10 [2] 6b 25 [2] 45 25 [2] 7a 39 }

  condition:
    any of them
}