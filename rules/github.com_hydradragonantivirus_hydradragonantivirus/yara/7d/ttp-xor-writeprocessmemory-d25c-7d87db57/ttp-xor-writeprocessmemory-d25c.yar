rule TTP_XOR_WriteProcessMemory_d25c {
  strings:
    $key_d25c = { 85 2e [2] b7 0c [2] b1 39 [2] 9f 39 [2] a0 25 }

  condition:
    any of them
}