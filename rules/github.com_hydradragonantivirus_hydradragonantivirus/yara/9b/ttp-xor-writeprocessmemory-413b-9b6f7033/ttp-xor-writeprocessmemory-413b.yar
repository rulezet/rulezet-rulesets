rule TTP_XOR_WriteProcessMemory_413b {
  strings:
    $key_413b = { 16 49 [2] 24 6b [2] 22 5e [2] 0c 5e [2] 33 42 }

  condition:
    any of them
}