rule TTP_XOR_WriteProcessMemory_ed13 {
  strings:
    $key_ed13 = { ba 61 [2] 88 43 [2] 8e 76 [2] a0 76 [2] 9f 6a }

  condition:
    any of them
}