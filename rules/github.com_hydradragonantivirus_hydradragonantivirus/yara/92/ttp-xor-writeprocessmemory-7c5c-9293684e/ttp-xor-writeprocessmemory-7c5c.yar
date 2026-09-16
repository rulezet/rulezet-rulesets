rule TTP_XOR_WriteProcessMemory_7c5c {
  strings:
    $key_7c5c = { 2b 2e [2] 19 0c [2] 1f 39 [2] 31 39 [2] 0e 25 }

  condition:
    any of them
}