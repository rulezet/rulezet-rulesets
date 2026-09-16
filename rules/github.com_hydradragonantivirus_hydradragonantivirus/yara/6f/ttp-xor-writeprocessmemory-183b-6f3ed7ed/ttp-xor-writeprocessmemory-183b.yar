rule TTP_XOR_WriteProcessMemory_183b {
  strings:
    $key_183b = { 4f 49 [2] 7d 6b [2] 7b 5e [2] 55 5e [2] 6a 42 }

  condition:
    any of them
}