rule TTP_XOR_WriteProcessMemory_ed76 {
  strings:
    $key_ed76 = { ba 04 [2] 88 26 [2] 8e 13 [2] a0 13 [2] 9f 0f }

  condition:
    any of them
}