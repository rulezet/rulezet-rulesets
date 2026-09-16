rule TTP_XOR_WriteProcessMemory_d23b {
  strings:
    $key_d23b = { 85 49 [2] b7 6b [2] b1 5e [2] 9f 5e [2] a0 42 }

  condition:
    any of them
}