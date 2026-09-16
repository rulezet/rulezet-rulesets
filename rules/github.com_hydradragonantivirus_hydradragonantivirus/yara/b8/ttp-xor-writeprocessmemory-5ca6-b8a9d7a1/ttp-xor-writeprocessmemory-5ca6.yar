rule TTP_XOR_WriteProcessMemory_5ca6 {
  strings:
    $key_5ca6 = { 0b d4 [2] 39 f6 [2] 3f c3 [2] 11 c3 [2] 2e df }

  condition:
    any of them
}