rule TTP_XOR_WriteProcessMemory_c559 {
  strings:
    $key_c559 = { 92 2b [2] a0 09 [2] a6 3c [2] 88 3c [2] b7 20 }

  condition:
    any of them
}