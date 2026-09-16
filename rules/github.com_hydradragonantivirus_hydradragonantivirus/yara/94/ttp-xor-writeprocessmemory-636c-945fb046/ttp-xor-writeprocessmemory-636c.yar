rule TTP_XOR_WriteProcessMemory_636c {
  strings:
    $key_636c = { 34 1e [2] 06 3c [2] 00 09 [2] 2e 09 [2] 11 15 }

  condition:
    any of them
}