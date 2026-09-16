rule TTP_XOR_WriteProcessMemory_d67e {
  strings:
    $key_d67e = { 81 0c [2] b3 2e [2] b5 1b [2] 9b 1b [2] a4 07 }

  condition:
    any of them
}