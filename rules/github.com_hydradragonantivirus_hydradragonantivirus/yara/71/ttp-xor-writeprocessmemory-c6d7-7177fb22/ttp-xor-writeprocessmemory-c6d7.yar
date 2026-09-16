rule TTP_XOR_WriteProcessMemory_c6d7 {
  strings:
    $key_c6d7 = { 91 a5 [2] a3 87 [2] a5 b2 [2] 8b b2 [2] b4 ae }

  condition:
    any of them
}