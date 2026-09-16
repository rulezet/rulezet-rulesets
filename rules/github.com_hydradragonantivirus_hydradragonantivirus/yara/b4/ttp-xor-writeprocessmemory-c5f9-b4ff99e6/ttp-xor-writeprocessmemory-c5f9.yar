rule TTP_XOR_WriteProcessMemory_c5f9 {
  strings:
    $key_c5f9 = { 92 8b [2] a0 a9 [2] a6 9c [2] 88 9c [2] b7 80 }

  condition:
    any of them
}