rule TTP_XOR_WriteProcessMemory_d3db {
  strings:
    $key_d3db = { 84 a9 [2] b6 8b [2] b0 be [2] 9e be [2] a1 a2 }

  condition:
    any of them
}