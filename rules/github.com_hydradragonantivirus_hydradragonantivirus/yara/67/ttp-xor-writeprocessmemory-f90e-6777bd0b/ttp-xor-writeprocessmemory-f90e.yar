rule TTP_XOR_WriteProcessMemory_f90e {
  strings:
    $key_f90e = { ae 7c [2] 9c 5e [2] 9a 6b [2] b4 6b [2] 8b 77 }

  condition:
    any of them
}