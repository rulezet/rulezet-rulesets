rule TTP_XOR_WriteProcessMemory_c57e {
  strings:
    $key_c57e = { 92 0c [2] a0 2e [2] a6 1b [2] 88 1b [2] b7 07 }

  condition:
    any of them
}