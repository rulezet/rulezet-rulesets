rule TTP_XOR_WriteProcessMemory_ca94 {
  strings:
    $key_ca94 = { 9d e6 [2] af c4 [2] a9 f1 [2] 87 f1 [2] b8 ed }

  condition:
    any of them
}