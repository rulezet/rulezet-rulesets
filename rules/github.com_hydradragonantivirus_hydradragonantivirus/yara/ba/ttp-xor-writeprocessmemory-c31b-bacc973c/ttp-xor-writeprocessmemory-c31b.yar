rule TTP_XOR_WriteProcessMemory_c31b {
  strings:
    $key_c31b = { 94 69 [2] a6 4b [2] a0 7e [2] 8e 7e [2] b1 62 }

  condition:
    any of them
}