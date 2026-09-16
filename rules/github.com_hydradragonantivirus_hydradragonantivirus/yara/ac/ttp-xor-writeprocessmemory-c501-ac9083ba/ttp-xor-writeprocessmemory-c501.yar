rule TTP_XOR_WriteProcessMemory_c501 {
  strings:
    $key_c501 = { 92 73 [2] a0 51 [2] a6 64 [2] 88 64 [2] b7 78 }

  condition:
    any of them
}