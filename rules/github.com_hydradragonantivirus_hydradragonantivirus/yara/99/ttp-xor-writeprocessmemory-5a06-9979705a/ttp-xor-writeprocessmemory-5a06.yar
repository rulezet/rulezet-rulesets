rule TTP_XOR_WriteProcessMemory_5a06 {
  strings:
    $key_5a06 = { 0d 74 [2] 3f 56 [2] 39 63 [2] 17 63 [2] 28 7f }

  condition:
    any of them
}