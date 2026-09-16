rule TTP_XOR_WriteProcessMemory_d16c {
  strings:
    $key_d16c = { 86 1e [2] b4 3c [2] b2 09 [2] 9c 09 [2] a3 15 }

  condition:
    any of them
}