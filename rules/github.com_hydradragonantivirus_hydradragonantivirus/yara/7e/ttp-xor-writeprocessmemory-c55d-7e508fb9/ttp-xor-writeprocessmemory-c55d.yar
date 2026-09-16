rule TTP_XOR_WriteProcessMemory_c55d {
  strings:
    $key_c55d = { 92 2f [2] a0 0d [2] a6 38 [2] 88 38 [2] b7 24 }

  condition:
    any of them
}