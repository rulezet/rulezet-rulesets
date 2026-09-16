rule TTP_XOR_WriteProcessMemory_ed37 {
  strings:
    $key_ed37 = { ba 45 [2] 88 67 [2] 8e 52 [2] a0 52 [2] 9f 4e }

  condition:
    any of them
}