rule TTP_XOR_WriteProcessMemory_ed15 {
  strings:
    $key_ed15 = { ba 67 [2] 88 45 [2] 8e 70 [2] a0 70 [2] 9f 6c }

  condition:
    any of them
}