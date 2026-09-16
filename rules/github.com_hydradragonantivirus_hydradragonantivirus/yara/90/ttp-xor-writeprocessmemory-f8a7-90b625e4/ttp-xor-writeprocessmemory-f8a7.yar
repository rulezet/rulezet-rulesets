rule TTP_XOR_WriteProcessMemory_f8a7 {
  strings:
    $key_f8a7 = { af d5 [2] 9d f7 [2] 9b c2 [2] b5 c2 [2] 8a de }

  condition:
    any of them
}