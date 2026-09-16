rule TTP_XOR_WriteProcessMemory_ed32 {
  strings:
    $key_ed32 = { ba 40 [2] 88 62 [2] 8e 57 [2] a0 57 [2] 9f 4b }

  condition:
    any of them
}