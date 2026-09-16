rule TTP_XOR_WriteProcessMemory_c34c {
  strings:
    $key_c34c = { 94 3e [2] a6 1c [2] a0 29 [2] 8e 29 [2] b1 35 }

  condition:
    any of them
}