rule TTP_XOR_WriteProcessMemory_c22c {
  strings:
    $key_c22c = { 95 5e [2] a7 7c [2] a1 49 [2] 8f 49 [2] b0 55 }

  condition:
    any of them
}