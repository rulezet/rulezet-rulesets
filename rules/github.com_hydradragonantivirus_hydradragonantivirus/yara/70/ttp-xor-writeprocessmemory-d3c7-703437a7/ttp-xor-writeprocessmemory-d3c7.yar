rule TTP_XOR_WriteProcessMemory_d3c7 {
  strings:
    $key_d3c7 = { 84 b5 [2] b6 97 [2] b0 a2 [2] 9e a2 [2] a1 be }

  condition:
    any of them
}