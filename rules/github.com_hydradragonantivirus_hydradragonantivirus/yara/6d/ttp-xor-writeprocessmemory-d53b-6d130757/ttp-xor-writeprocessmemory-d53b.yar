rule TTP_XOR_WriteProcessMemory_d53b {
  strings:
    $key_d53b = { 82 49 [2] b0 6b [2] b6 5e [2] 98 5e [2] a7 42 }

  condition:
    any of them
}