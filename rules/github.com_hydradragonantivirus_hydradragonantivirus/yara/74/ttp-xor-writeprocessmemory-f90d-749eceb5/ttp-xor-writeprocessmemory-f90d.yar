rule TTP_XOR_WriteProcessMemory_f90d {
  strings:
    $key_f90d = { ae 7f [2] 9c 5d [2] 9a 68 [2] b4 68 [2] 8b 74 }

  condition:
    any of them
}