rule TTP_XOR_WriteProcessMemory_d77b {
  strings:
    $key_d77b = { 80 09 [2] b2 2b [2] b4 1e [2] 9a 1e [2] a5 02 }

  condition:
    any of them
}