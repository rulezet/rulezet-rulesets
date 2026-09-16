rule TTP_XOR_WriteProcessMemory_c73c {
  strings:
    $key_c73c = { 90 4e [2] a2 6c [2] a4 59 [2] 8a 59 [2] b5 45 }

  condition:
    any of them
}