rule TTP_XOR_WriteProcessMemory_0826 {
  strings:
    $key_0826 = { 5f 54 [2] 6d 76 [2] 6b 43 [2] 45 43 [2] 7a 5f }

  condition:
    any of them
}