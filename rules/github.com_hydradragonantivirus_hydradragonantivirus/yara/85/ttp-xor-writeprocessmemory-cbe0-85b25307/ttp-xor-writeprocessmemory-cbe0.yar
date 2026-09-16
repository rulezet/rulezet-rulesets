rule TTP_XOR_WriteProcessMemory_cbe0 {
  strings:
    $key_cbe0 = { 9c 92 [2] ae b0 [2] a8 85 [2] 86 85 [2] b9 99 }

  condition:
    any of them
}