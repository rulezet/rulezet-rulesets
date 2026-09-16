rule TTP_XOR_WriteProcessMemory_0841 {
  strings:
    $key_0841 = { 5f 33 [2] 6d 11 [2] 6b 24 [2] 45 24 [2] 7a 38 }

  condition:
    any of them
}