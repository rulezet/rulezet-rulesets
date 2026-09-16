rule TTP_XOR_WriteProcessMemory_331c {
  strings:
    $key_331c = { 64 6e [2] 56 4c [2] 50 79 [2] 7e 79 [2] 41 65 }

  condition:
    any of them
}