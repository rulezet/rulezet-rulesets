rule TTP_XOR_WriteProcessMemory_c2d7 {
  strings:
    $key_c2d7 = { 95 a5 [2] a7 87 [2] a1 b2 [2] 8f b2 [2] b0 ae }

  condition:
    any of them
}