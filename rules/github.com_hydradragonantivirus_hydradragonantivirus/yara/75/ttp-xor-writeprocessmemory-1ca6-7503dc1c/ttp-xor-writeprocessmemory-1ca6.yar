rule TTP_XOR_WriteProcessMemory_1ca6 {
  strings:
    $key_1ca6 = { 4b d4 [2] 79 f6 [2] 7f c3 [2] 51 c3 [2] 6e df }

  condition:
    any of them
}