rule TTP_XOR_WriteProcessMemory_d33b {
  strings:
    $key_d33b = { 84 49 [2] b6 6b [2] b0 5e [2] 9e 5e [2] a1 42 }

  condition:
    any of them
}