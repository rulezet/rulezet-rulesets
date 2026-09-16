rule TTP_XOR_WriteProcessMemory_575c {
  strings:
    $key_575c = { 00 2e [2] 32 0c [2] 34 39 [2] 1a 39 [2] 25 25 }

  condition:
    any of them
}