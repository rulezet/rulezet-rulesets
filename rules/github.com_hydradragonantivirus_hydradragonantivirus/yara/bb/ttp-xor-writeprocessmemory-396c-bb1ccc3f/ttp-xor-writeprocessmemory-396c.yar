rule TTP_XOR_WriteProcessMemory_396c {
  strings:
    $key_396c = { 6e 1e [2] 5c 3c [2] 5a 09 [2] 74 09 [2] 4b 15 }

  condition:
    any of them
}