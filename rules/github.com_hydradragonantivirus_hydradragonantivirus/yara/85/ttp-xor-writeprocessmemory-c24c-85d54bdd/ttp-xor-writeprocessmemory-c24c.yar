rule TTP_XOR_WriteProcessMemory_c24c {
  strings:
    $key_c24c = { 95 3e [2] a7 1c [2] a1 29 [2] 8f 29 [2] b0 35 }

  condition:
    any of them
}