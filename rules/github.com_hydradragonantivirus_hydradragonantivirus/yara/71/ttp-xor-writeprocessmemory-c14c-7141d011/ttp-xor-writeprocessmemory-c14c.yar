rule TTP_XOR_WriteProcessMemory_c14c {
  strings:
    $key_c14c = { 96 3e [2] a4 1c [2] a2 29 [2] 8c 29 [2] b3 35 }

  condition:
    any of them
}