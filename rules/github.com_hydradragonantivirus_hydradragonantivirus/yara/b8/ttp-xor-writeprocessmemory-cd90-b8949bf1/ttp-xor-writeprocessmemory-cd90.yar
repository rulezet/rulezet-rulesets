rule TTP_XOR_WriteProcessMemory_cd90 {
  strings:
    $key_cd90 = { 9a e2 [2] a8 c0 [2] ae f5 [2] 80 f5 [2] bf e9 }

  condition:
    any of them
}