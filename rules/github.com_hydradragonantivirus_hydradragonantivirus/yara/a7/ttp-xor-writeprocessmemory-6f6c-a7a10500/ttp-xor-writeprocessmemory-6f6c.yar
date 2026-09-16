rule TTP_XOR_WriteProcessMemory_6f6c {
  strings:
    $key_6f6c = { 38 1e [2] 0a 3c [2] 0c 09 [2] 22 09 [2] 1d 15 }

  condition:
    any of them
}