rule TTP_XOR_WriteProcessMemory_d64c {
  strings:
    $key_d64c = { 81 3e [2] b3 1c [2] b5 29 [2] 9b 29 [2] a4 35 }

  condition:
    any of them
}