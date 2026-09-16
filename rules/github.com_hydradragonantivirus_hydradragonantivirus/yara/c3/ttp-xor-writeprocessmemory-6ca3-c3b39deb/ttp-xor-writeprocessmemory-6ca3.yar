rule TTP_XOR_WriteProcessMemory_6ca3 {
  strings:
    $key_6ca3 = { 3b d1 [2] 09 f3 [2] 0f c6 [2] 21 c6 [2] 1e da }

  condition:
    any of them
}