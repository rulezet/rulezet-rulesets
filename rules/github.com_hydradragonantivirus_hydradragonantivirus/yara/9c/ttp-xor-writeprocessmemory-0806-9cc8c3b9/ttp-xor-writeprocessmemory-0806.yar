rule TTP_XOR_WriteProcessMemory_0806 {
  strings:
    $key_0806 = { 5f 74 [2] 6d 56 [2] 6b 63 [2] 45 63 [2] 7a 7f }

  condition:
    any of them
}