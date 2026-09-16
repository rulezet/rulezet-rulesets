rule TTP_XOR_WriteProcessMemory_7d5c {
  strings:
    $key_7d5c = { 2a 2e [2] 18 0c [2] 1e 39 [2] 30 39 [2] 0f 25 }

  condition:
    any of them
}