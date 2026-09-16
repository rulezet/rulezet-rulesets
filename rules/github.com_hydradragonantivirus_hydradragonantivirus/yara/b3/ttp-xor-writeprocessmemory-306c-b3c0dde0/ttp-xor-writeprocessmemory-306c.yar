rule TTP_XOR_WriteProcessMemory_306c {
  strings:
    $key_306c = { 67 1e [2] 55 3c [2] 53 09 [2] 7d 09 [2] 42 15 }

  condition:
    any of them
}