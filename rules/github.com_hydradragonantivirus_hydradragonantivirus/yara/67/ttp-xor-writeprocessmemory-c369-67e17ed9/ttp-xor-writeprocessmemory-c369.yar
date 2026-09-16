rule TTP_XOR_WriteProcessMemory_c369 {
  strings:
    $key_c369 = { 94 1b [2] a6 39 [2] a0 0c [2] 8e 0c [2] b1 10 }

  condition:
    any of them
}