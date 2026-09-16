rule TTP_XOR_WriteProcessMemory_013b {
  strings:
    $key_013b = { 56 49 [2] 64 6b [2] 62 5e [2] 4c 5e [2] 73 42 }

  condition:
    any of them
}