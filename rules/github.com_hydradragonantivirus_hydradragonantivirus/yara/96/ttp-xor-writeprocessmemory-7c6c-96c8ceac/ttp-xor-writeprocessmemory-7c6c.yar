rule TTP_XOR_WriteProcessMemory_7c6c {
  strings:
    $key_7c6c = { 2b 1e [2] 19 3c [2] 1f 09 [2] 31 09 [2] 0e 15 }

  condition:
    any of them
}