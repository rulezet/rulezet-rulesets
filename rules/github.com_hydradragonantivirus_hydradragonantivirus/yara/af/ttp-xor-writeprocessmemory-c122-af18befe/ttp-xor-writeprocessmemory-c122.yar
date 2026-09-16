rule TTP_XOR_WriteProcessMemory_c122 {
  strings:
    $key_c122 = { 96 50 [2] a4 72 [2] a2 47 [2] 8c 47 [2] b3 5b }

  condition:
    any of them
}