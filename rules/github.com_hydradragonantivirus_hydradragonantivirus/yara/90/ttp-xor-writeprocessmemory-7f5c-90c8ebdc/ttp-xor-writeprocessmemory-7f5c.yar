rule TTP_XOR_WriteProcessMemory_7f5c {
  strings:
    $key_7f5c = { 28 2e [2] 1a 0c [2] 1c 39 [2] 32 39 [2] 0d 25 }

  condition:
    any of them
}