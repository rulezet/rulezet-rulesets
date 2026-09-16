rule TTP_XOR_WriteProcessMemory_c30c {
  strings:
    $key_c30c = { 94 7e [2] a6 5c [2] a0 69 [2] 8e 69 [2] b1 75 }

  condition:
    any of them
}