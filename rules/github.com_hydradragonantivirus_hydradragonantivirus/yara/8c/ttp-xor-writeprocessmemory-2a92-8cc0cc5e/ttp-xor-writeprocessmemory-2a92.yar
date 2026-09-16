rule TTP_XOR_WriteProcessMemory_2a92 {
  strings:
    $key_2a92 = { 7d e0 [2] 4f c2 [2] 49 f7 [2] 67 f7 [2] 58 eb }

  condition:
    any of them
}