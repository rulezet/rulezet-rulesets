rule TTP_XOR_WriteProcessMemory_596e {
  strings:
    $key_596e = { 0e 1c [2] 3c 3e [2] 3a 0b [2] 14 0b [2] 2b 17 }

  condition:
    any of them
}