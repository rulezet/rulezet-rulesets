rule TTP_XOR_WriteProcessMemory_d57e {
  strings:
    $key_d57e = { 82 0c [2] b0 2e [2] b6 1b [2] 98 1b [2] a7 07 }

  condition:
    any of them
}