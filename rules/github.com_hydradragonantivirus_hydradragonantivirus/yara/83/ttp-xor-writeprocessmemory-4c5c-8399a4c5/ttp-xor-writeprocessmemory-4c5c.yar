rule TTP_XOR_WriteProcessMemory_4c5c {
  strings:
    $key_4c5c = { 1b 2e [2] 29 0c [2] 2f 39 [2] 01 39 [2] 3e 25 }

  condition:
    any of them
}