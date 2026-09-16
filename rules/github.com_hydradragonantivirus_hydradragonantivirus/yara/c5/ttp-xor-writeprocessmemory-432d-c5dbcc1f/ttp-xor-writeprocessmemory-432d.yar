rule TTP_XOR_WriteProcessMemory_432d {
  strings:
    $key_432d = { 14 5f [2] 26 7d [2] 20 48 [2] 0e 48 [2] 31 54 }

  condition:
    any of them
}