rule TTP_XOR_WriteProcessMemory_7f6c {
  strings:
    $key_7f6c = { 28 1e [2] 1a 3c [2] 1c 09 [2] 32 09 [2] 0d 15 }

  condition:
    any of them
}