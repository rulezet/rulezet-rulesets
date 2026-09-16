rule TTP_XOR_WriteProcessMemory_c7d7 {
  strings:
    $key_c7d7 = { 90 a5 [2] a2 87 [2] a4 b2 [2] 8a b2 [2] b5 ae }

  condition:
    any of them
}