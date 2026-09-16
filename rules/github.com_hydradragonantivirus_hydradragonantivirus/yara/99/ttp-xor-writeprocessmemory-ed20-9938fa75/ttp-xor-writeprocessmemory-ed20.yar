rule TTP_XOR_WriteProcessMemory_ed20 {
  strings:
    $key_ed20 = { ba 52 [2] 88 70 [2] 8e 45 [2] a0 45 [2] 9f 59 }

  condition:
    any of them
}