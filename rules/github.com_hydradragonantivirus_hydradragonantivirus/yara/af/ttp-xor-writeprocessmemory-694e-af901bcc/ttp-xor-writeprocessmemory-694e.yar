rule TTP_XOR_WriteProcessMemory_694e {
  strings:
    $key_694e = { 3e 3c [2] 0c 1e [2] 0a 2b [2] 24 2b [2] 1b 37 }

  condition:
    any of them
}