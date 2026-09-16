rule TTP_XOR_WriteProcessMemory_c41b {
  strings:
    $key_c41b = { 93 69 [2] a1 4b [2] a7 7e [2] 89 7e [2] b6 62 }

  condition:
    any of them
}