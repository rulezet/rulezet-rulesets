rule TTP_XOR_WriteProcessMemory_f57b {
  strings:
    $key_f57b = { a2 09 [2] 90 2b [2] 96 1e [2] b8 1e [2] 87 02 }

  condition:
    any of them
}