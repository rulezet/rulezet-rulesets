rule TTP_XOR_WriteProcessMemory_ed25 {
  strings:
    $key_ed25 = { ba 57 [2] 88 75 [2] 8e 40 [2] a0 40 [2] 9f 5c }

  condition:
    any of them
}