rule TTP_XOR_WriteProcessMemory_d54e {
  strings:
    $key_d54e = { 82 3c [2] b0 1e [2] b6 2b [2] 98 2b [2] a7 37 }

  condition:
    any of them
}