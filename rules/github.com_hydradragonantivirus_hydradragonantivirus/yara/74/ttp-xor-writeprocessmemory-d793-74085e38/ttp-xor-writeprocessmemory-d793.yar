rule TTP_XOR_WriteProcessMemory_d793 {
  strings:
    $key_d793 = { 80 e1 [2] b2 c3 [2] b4 f6 [2] 9a f6 [2] a5 ea }

  condition:
    any of them
}