rule TTP_XOR_WriteProcessMemory_0446 {
  strings:
    $key_0446 = { 53 34 [2] 61 16 [2] 67 23 [2] 49 23 [2] 76 3f }

  condition:
    any of them
}