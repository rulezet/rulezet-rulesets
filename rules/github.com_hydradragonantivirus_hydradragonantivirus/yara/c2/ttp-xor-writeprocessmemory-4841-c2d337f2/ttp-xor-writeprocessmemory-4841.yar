rule TTP_XOR_WriteProcessMemory_4841 {
  strings:
    $key_4841 = { 1f 33 [2] 2d 11 [2] 2b 24 [2] 05 24 [2] 3a 38 }

  condition:
    any of them
}