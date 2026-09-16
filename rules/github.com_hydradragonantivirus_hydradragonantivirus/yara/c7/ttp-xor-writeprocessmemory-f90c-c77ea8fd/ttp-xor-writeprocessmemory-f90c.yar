rule TTP_XOR_WriteProcessMemory_f90c {
  strings:
    $key_f90c = { ae 7e [2] 9c 5c [2] 9a 69 [2] b4 69 [2] 8b 75 }

  condition:
    any of them
}