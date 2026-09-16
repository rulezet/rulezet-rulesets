rule TTP_XOR_WriteProcessMemory_c797 {
  strings:
    $key_c797 = { 90 e5 [2] a2 c7 [2] a4 f2 [2] 8a f2 [2] b5 ee }

  condition:
    any of them
}