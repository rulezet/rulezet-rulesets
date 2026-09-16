rule TTP_XOR_WriteProcessMemory_c7e2 {
  strings:
    $key_c7e2 = { 90 90 [2] a2 b2 [2] a4 87 [2] 8a 87 [2] b5 9b }

  condition:
    any of them
}