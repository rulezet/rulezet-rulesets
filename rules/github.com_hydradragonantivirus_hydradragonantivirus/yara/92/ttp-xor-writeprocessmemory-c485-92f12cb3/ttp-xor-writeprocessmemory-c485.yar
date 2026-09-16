rule TTP_XOR_WriteProcessMemory_c485 {
  strings:
    $key_c485 = { 93 f7 [2] a1 d5 [2] a7 e0 [2] 89 e0 [2] b6 fc }

  condition:
    any of them
}