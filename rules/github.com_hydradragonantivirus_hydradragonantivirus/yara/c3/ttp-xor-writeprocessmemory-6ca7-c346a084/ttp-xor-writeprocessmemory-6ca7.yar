rule TTP_XOR_WriteProcessMemory_6ca7 {
  strings:
    $key_6ca7 = { 3b d5 [2] 09 f7 [2] 0f c2 [2] 21 c2 [2] 1e de }

  condition:
    any of them
}