rule TTP_XOR_WriteProcessMemory_fcd0 {
  strings:
    $key_fcd0 = { ab a2 [2] 99 80 [2] 9f b5 [2] b1 b5 [2] 8e a9 }

  condition:
    any of them
}