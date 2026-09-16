rule TTP_XOR_WriteProcessMemory_1e4c {
  strings:
    $key_1e4c = { 49 3e [2] 7b 1c [2] 7d 29 [2] 53 29 [2] 6c 35 }

  condition:
    any of them
}