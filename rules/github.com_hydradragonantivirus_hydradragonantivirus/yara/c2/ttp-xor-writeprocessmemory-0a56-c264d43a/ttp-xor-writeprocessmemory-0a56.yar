rule TTP_XOR_WriteProcessMemory_0a56 {
  strings:
    $key_0a56 = { 5d 24 [2] 6f 06 [2] 69 33 [2] 47 33 [2] 78 2f }

  condition:
    any of them
}