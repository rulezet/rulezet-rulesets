rule TTP_XOR_WriteProcessMemory_f90b {
  strings:
    $key_f90b = { ae 79 [2] 9c 5b [2] 9a 6e [2] b4 6e [2] 8b 72 }

  condition:
    any of them
}