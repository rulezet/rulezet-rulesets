rule TTP_XOR_WriteProcessMemory_217b {
  strings:
    $key_217b = { 76 09 [2] 44 2b [2] 42 1e [2] 6c 1e [2] 53 02 }

  condition:
    any of them
}