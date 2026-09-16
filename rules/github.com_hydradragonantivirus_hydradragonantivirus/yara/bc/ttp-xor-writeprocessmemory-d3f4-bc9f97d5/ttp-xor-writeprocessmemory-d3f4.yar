rule TTP_XOR_WriteProcessMemory_d3f4 {
  strings:
    $key_d3f4 = { 84 86 [2] b6 a4 [2] b0 91 [2] 9e 91 [2] a1 8d }

  condition:
    any of them
}