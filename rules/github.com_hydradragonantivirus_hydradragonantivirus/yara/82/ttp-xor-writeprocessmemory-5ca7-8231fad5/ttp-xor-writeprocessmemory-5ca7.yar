rule TTP_XOR_WriteProcessMemory_5ca7 {
  strings:
    $key_5ca7 = { 0b d5 [2] 39 f7 [2] 3f c2 [2] 11 c2 [2] 2e de }

  condition:
    any of them
}