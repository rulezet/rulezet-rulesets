rule TTP_XOR_WriteProcessMemory_1e6c {
  strings:
    $key_1e6c = { 49 1e [2] 7b 3c [2] 7d 09 [2] 53 09 [2] 6c 15 }

  condition:
    any of them
}