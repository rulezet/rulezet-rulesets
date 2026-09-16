rule TTP_XOR_WriteProcessMemory_7e5c {
  strings:
    $key_7e5c = { 29 2e [2] 1b 0c [2] 1d 39 [2] 33 39 [2] 0c 25 }

  condition:
    any of them
}