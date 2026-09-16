rule TTP_XOR_WriteProcessMemory_d14c {
  strings:
    $key_d14c = { 86 3e [2] b4 1c [2] b2 29 [2] 9c 29 [2] a3 35 }

  condition:
    any of them
}