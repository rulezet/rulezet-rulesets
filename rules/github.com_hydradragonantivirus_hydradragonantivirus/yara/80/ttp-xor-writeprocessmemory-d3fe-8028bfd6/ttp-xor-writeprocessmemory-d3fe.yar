rule TTP_XOR_WriteProcessMemory_d3fe {
  strings:
    $key_d3fe = { 84 8c [2] b6 ae [2] b0 9b [2] 9e 9b [2] a1 87 }

  condition:
    any of them
}