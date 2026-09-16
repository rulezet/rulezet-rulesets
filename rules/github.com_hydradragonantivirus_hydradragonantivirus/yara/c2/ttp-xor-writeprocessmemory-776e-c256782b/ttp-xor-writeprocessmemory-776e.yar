rule TTP_XOR_WriteProcessMemory_776e {
  strings:
    $key_776e = { 20 1c [2] 12 3e [2] 14 0b [2] 3a 0b [2] 05 17 }

  condition:
    any of them
}