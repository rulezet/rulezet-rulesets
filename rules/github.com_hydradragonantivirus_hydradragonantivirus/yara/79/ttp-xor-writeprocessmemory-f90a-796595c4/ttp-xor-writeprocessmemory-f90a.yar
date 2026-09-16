rule TTP_XOR_WriteProcessMemory_f90a {
  strings:
    $key_f90a = { ae 78 [2] 9c 5a [2] 9a 6f [2] b4 6f [2] 8b 73 }

  condition:
    any of them
}