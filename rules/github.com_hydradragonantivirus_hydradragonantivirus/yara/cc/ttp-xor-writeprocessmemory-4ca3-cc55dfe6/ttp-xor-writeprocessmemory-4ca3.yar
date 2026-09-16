rule TTP_XOR_WriteProcessMemory_4ca3 {
  strings:
    $key_4ca3 = { 1b d1 [2] 29 f3 [2] 2f c6 [2] 01 c6 [2] 3e da }

  condition:
    any of them
}