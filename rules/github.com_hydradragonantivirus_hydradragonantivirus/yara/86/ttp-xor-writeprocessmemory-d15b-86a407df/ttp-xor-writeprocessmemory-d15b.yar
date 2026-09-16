rule TTP_XOR_WriteProcessMemory_d15b {
  strings:
    $key_d15b = { 86 29 [2] b4 0b [2] b2 3e [2] 9c 3e [2] a3 22 }

  condition:
    any of them
}