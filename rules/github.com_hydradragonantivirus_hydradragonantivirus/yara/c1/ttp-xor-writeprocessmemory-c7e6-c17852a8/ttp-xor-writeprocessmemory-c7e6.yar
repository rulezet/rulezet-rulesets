rule TTP_XOR_WriteProcessMemory_c7e6 {
  strings:
    $key_c7e6 = { 90 94 [2] a2 b6 [2] a4 83 [2] 8a 83 [2] b5 9f }

  condition:
    any of them
}