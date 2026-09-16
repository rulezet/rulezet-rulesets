rule TTP_XOR_WriteProcessMemory_c04c {
  strings:
    $key_c04c = { 97 3e [2] a5 1c [2] a3 29 [2] 8d 29 [2] b2 35 }

  condition:
    any of them
}