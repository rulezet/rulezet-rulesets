rule TTP_XOR_WriteProcessMemory_d3cb {
  strings:
    $key_d3cb = { 84 b9 [2] b6 9b [2] b0 ae [2] 9e ae [2] a1 b2 }

  condition:
    any of them
}