rule TTP_XOR_WriteProcessMemory_ed43 {
  strings:
    $key_ed43 = { ba 31 [2] 88 13 [2] 8e 26 [2] a0 26 [2] 9f 3a }

  condition:
    any of them
}