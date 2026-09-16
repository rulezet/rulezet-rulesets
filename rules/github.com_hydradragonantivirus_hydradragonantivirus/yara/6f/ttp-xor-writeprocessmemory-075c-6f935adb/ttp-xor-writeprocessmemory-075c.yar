rule TTP_XOR_WriteProcessMemory_075c {
  strings:
    $key_075c = { 50 2e [2] 62 0c [2] 64 39 [2] 4a 39 [2] 75 25 }

  condition:
    any of them
}