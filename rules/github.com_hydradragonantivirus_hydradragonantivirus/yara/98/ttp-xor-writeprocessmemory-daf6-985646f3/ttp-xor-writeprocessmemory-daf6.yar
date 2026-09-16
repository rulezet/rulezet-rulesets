rule TTP_XOR_WriteProcessMemory_daf6 {
  strings:
    $key_daf6 = { 8d 84 [2] bf a6 [2] b9 93 [2] 97 93 [2] a8 8f }

  condition:
    any of them
}