rule TTP_XOR_WriteProcessMemory_d51b {
  strings:
    $key_d51b = { 82 69 [2] b0 4b [2] b6 7e [2] 98 7e [2] a7 62 }

  condition:
    any of them
}