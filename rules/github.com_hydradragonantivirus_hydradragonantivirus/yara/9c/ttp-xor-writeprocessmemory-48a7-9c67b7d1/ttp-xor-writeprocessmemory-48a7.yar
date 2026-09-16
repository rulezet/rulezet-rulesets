rule TTP_XOR_WriteProcessMemory_48a7 {
  strings:
    $key_48a7 = { 1f d5 [2] 2d f7 [2] 2b c2 [2] 05 c2 [2] 3a de }

  condition:
    any of them
}