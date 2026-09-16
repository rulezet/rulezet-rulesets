rule TTP_XOR_WriteProcessMemory_c359 {
  strings:
    $key_c359 = { 94 2b [2] a6 09 [2] a0 3c [2] 8e 3c [2] b1 20 }

  condition:
    any of them
}