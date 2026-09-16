rule TTP_XOR_WriteProcessMemory_c51b {
  strings:
    $key_c51b = { 92 69 [2] a0 4b [2] a6 7e [2] 88 7e [2] b7 62 }

  condition:
    any of them
}