rule TTP_XOR_WriteProcessMemory_306e {
  strings:
    $key_306e = { 67 1c [2] 55 3e [2] 53 0b [2] 7d 0b [2] 42 17 }

  condition:
    any of them
}