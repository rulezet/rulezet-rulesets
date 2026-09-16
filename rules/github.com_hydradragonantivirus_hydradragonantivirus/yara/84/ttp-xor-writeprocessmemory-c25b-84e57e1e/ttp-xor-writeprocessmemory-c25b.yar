rule TTP_XOR_WriteProcessMemory_c25b {
  strings:
    $key_c25b = { 95 29 [2] a7 0b [2] a1 3e [2] 8f 3e [2] b0 22 }

  condition:
    any of them
}