rule TTP_XOR_WriteProcessMemory_4ca6 {
  strings:
    $key_4ca6 = { 1b d4 [2] 29 f6 [2] 2f c3 [2] 01 c3 [2] 3e df }

  condition:
    any of them
}