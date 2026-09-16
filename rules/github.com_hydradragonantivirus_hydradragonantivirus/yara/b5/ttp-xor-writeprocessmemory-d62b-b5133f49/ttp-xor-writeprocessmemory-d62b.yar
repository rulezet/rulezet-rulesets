rule TTP_XOR_WriteProcessMemory_d62b {
  strings:
    $key_d62b = { 81 59 [2] b3 7b [2] b5 4e [2] 9b 4e [2] a4 52 }

  condition:
    any of them
}