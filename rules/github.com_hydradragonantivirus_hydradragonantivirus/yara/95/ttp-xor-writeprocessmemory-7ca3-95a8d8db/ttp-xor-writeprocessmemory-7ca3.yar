rule TTP_XOR_WriteProcessMemory_7ca3 {
  strings:
    $key_7ca3 = { 2b d1 [2] 19 f3 [2] 1f c6 [2] 31 c6 [2] 0e da }

  condition:
    any of them
}