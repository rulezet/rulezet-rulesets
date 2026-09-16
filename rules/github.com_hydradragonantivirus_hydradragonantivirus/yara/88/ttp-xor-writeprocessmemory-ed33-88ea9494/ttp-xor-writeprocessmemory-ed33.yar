rule TTP_XOR_WriteProcessMemory_ed33 {
  strings:
    $key_ed33 = { ba 41 [2] 88 63 [2] 8e 56 [2] a0 56 [2] 9f 4a }

  condition:
    any of them
}