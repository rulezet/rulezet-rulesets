rule TTP_XOR_WriteProcessMemory_d3e3 {
  strings:
    $key_d3e3 = { 84 91 [2] b6 b3 [2] b0 86 [2] 9e 86 [2] a1 9a }

  condition:
    any of them
}