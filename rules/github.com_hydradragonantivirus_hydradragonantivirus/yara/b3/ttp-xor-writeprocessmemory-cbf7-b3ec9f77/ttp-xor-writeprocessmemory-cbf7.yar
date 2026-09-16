rule TTP_XOR_WriteProcessMemory_cbf7 {
  strings:
    $key_cbf7 = { 9c 85 [2] ae a7 [2] a8 92 [2] 86 92 [2] b9 8e }

  condition:
    any of them
}