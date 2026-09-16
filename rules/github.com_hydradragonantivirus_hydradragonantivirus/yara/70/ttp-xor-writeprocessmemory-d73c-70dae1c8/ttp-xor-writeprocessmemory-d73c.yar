rule TTP_XOR_WriteProcessMemory_d73c {
  strings:
    $key_d73c = { 80 4e [2] b2 6c [2] b4 59 [2] 9a 59 [2] a5 45 }

  condition:
    any of them
}