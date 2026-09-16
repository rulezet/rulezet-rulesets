rule TTP_XOR_WriteProcessMemory_5a26 {
  strings:
    $key_5a26 = { 0d 54 [2] 3f 76 [2] 39 43 [2] 17 43 [2] 28 5f }

  condition:
    any of them
}