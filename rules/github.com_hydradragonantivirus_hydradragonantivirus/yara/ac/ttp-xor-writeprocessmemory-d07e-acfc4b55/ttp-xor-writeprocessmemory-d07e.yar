rule TTP_XOR_WriteProcessMemory_d07e {
  strings:
    $key_d07e = { 87 0c [2] b5 2e [2] b3 1b [2] 9d 1b [2] a2 07 }

  condition:
    any of them
}