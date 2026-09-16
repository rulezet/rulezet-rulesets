rule TTP_XOR_WriteProcessMemory_487b {
  strings:
    $key_487b = { 1f 09 [2] 2d 2b [2] 2b 1e [2] 05 1e [2] 3a 02 }

  condition:
    any of them
}