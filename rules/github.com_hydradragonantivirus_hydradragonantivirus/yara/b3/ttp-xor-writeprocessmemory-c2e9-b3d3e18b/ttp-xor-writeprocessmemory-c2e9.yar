rule TTP_XOR_WriteProcessMemory_c2e9 {
  strings:
    $key_c2e9 = { 95 9b [2] a7 b9 [2] a1 8c [2] 8f 8c [2] b0 90 }

  condition:
    any of them
}