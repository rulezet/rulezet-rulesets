rule TTP_XOR_WriteProcessMemory_3546 {
  strings:
    $key_3546 = { 62 34 [2] 50 16 [2] 56 23 [2] 78 23 [2] 47 3f }

  condition:
    any of them
}