rule TTP_XOR_WriteProcessMemory_d71c {
  strings:
    $key_d71c = { 80 6e [2] b2 4c [2] b4 79 [2] 9a 79 [2] a5 65 }

  condition:
    any of them
}