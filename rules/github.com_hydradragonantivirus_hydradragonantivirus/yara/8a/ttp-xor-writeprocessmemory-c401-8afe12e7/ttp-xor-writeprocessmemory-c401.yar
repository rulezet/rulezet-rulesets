rule TTP_XOR_WriteProcessMemory_c401 {
  strings:
    $key_c401 = { 93 73 [2] a1 51 [2] a7 64 [2] 89 64 [2] b6 78 }

  condition:
    any of them
}