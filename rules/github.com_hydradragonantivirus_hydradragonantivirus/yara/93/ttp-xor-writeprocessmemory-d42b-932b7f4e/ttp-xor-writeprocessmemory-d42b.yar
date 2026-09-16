rule TTP_XOR_WriteProcessMemory_d42b {
  strings:
    $key_d42b = { 83 59 [2] b1 7b [2] b7 4e [2] 99 4e [2] a6 52 }

  condition:
    any of them
}