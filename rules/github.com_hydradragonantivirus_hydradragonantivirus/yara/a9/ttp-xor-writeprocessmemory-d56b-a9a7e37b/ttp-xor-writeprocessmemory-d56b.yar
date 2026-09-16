rule TTP_XOR_WriteProcessMemory_d56b {
  strings:
    $key_d56b = { 82 19 [2] b0 3b [2] b6 0e [2] 98 0e [2] a7 12 }

  condition:
    any of them
}