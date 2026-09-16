rule TTP_XOR_WriteProcessMemory_d797 {
  strings:
    $key_d797 = { 80 e5 [2] b2 c7 [2] b4 f2 [2] 9a f2 [2] a5 ee }

  condition:
    any of them
}