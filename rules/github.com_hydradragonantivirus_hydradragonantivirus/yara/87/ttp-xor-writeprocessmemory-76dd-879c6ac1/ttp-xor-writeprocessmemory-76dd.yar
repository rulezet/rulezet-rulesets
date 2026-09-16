rule TTP_XOR_WriteProcessMemory_76dd {
  strings:
    $key_76dd = { 21 af [2] 13 8d [2] 15 b8 [2] 3b b8 [2] 04 a4 }

  condition:
    any of them
}