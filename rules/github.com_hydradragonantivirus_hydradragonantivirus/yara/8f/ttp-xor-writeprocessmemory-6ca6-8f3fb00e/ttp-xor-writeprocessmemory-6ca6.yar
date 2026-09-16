rule TTP_XOR_WriteProcessMemory_6ca6 {
  strings:
    $key_6ca6 = { 3b d4 [2] 09 f6 [2] 0f c3 [2] 21 c3 [2] 1e df }

  condition:
    any of them
}