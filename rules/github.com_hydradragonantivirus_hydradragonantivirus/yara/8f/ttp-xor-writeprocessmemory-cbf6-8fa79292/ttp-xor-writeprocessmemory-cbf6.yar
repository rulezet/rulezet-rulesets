rule TTP_XOR_WriteProcessMemory_cbf6 {
  strings:
    $key_cbf6 = { 9c 84 [2] ae a6 [2] a8 93 [2] 86 93 [2] b9 8f }

  condition:
    any of them
}