rule TTP_XOR_WriteProcessMemory_c48b {
  strings:
    $key_c48b = { 93 f9 [2] a1 db [2] a7 ee [2] 89 ee [2] b6 f2 }

  condition:
    any of them
}