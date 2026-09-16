rule TTP_XOR_WriteProcessMemory_c249 {
  strings:
    $key_c249 = { 95 3b [2] a7 19 [2] a1 2c [2] 8f 2c [2] b0 30 }

  condition:
    any of them
}