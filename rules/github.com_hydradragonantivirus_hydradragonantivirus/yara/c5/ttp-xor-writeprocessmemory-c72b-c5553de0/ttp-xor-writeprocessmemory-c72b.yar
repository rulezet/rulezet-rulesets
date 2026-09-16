rule TTP_XOR_WriteProcessMemory_c72b {
  strings:
    $key_c72b = { 90 59 [2] a2 7b [2] a4 4e [2] 8a 4e [2] b5 52 }

  condition:
    any of them
}