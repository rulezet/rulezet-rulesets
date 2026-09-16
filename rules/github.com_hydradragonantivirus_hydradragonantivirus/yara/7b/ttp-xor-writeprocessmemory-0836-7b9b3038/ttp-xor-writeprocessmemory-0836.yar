rule TTP_XOR_WriteProcessMemory_0836 {
  strings:
    $key_0836 = { 5f 44 [2] 6d 66 [2] 6b 53 [2] 45 53 [2] 7a 4f }

  condition:
    any of them
}