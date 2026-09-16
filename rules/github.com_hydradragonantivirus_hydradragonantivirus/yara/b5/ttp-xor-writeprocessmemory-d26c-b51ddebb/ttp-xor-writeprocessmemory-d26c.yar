rule TTP_XOR_WriteProcessMemory_d26c {
  strings:
    $key_d26c = { 85 1e [2] b7 3c [2] b1 09 [2] 9f 09 [2] a0 15 }

  condition:
    any of them
}