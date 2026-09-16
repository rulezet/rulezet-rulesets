rule TTP_XOR_WriteProcessMemory_d37b {
  strings:
    $key_d37b = { 84 09 [2] b6 2b [2] b0 1e [2] 9e 1e [2] a1 02 }

  condition:
    any of them
}