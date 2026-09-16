rule TTP_XOR_WriteProcessMemory_3ca6 {
  strings:
    $key_3ca6 = { 6b d4 [2] 59 f6 [2] 5f c3 [2] 71 c3 [2] 4e df }

  condition:
    any of them
}