rule TTP_XOR_WriteProcessMemory_d27e {
  strings:
    $key_d27e = { 85 0c [2] b7 2e [2] b1 1b [2] 9f 1b [2] a0 07 }

  condition:
    any of them
}