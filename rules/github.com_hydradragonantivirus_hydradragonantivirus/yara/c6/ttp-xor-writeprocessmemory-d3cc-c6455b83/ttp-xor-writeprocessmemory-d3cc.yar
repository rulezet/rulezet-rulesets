rule TTP_XOR_WriteProcessMemory_d3cc {
  strings:
    $key_d3cc = { 84 be [2] b6 9c [2] b0 a9 [2] 9e a9 [2] a1 b5 }

  condition:
    any of them
}