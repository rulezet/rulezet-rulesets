rule TTP_XOR_WriteProcessMemory_276e {
  strings:
    $key_276e = { 70 1c [2] 42 3e [2] 44 0b [2] 6a 0b [2] 55 17 }

  condition:
    any of them
}