rule TTP_XOR_WriteProcessMemory_d3f9 {
  strings:
    $key_d3f9 = { 84 8b [2] b6 a9 [2] b0 9c [2] 9e 9c [2] a1 80 }

  condition:
    any of them
}