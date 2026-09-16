rule TTP_XOR_WriteProcessMemory_5b5c {
  strings:
    $key_5b5c = { 0c 2e [2] 3e 0c [2] 38 39 [2] 16 39 [2] 29 25 }

  condition:
    any of them
}