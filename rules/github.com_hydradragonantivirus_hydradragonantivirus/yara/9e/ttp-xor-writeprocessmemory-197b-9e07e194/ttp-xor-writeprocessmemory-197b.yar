rule TTP_XOR_WriteProcessMemory_197b {
  strings:
    $key_197b = { 4e 09 [2] 7c 2b [2] 7a 1e [2] 54 1e [2] 6b 02 }

  condition:
    any of them
}