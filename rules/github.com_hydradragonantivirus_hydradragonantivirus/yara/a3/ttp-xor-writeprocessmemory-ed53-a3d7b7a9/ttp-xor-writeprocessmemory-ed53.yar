rule TTP_XOR_WriteProcessMemory_ed53 {
  strings:
    $key_ed53 = { ba 21 [2] 88 03 [2] 8e 36 [2] a0 36 [2] 9f 2a }

  condition:
    any of them
}