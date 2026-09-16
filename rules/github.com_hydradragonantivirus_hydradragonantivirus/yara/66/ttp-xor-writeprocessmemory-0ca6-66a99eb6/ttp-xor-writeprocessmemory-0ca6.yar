rule TTP_XOR_WriteProcessMemory_0ca6 {
  strings:
    $key_0ca6 = { 5b d4 [2] 69 f6 [2] 6f c3 [2] 41 c3 [2] 7e df }

  condition:
    any of them
}