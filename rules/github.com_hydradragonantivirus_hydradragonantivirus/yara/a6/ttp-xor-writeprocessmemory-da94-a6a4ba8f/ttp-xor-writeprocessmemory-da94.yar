rule TTP_XOR_WriteProcessMemory_da94 {
  strings:
    $key_da94 = { 8d e6 [2] bf c4 [2] b9 f1 [2] 97 f1 [2] a8 ed }

  condition:
    any of them
}