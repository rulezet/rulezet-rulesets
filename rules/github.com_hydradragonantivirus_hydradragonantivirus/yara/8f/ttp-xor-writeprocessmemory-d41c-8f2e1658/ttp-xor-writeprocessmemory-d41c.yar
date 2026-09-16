rule TTP_XOR_WriteProcessMemory_d41c {
  strings:
    $key_d41c = { 83 6e [2] b1 4c [2] b7 79 [2] 99 79 [2] a6 65 }

  condition:
    any of them
}