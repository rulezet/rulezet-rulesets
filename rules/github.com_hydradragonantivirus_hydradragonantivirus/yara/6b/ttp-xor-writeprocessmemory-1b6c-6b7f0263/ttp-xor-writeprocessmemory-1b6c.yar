rule TTP_XOR_WriteProcessMemory_1b6c {
  strings:
    $key_1b6c = { 4c 1e [2] 7e 3c [2] 78 09 [2] 56 09 [2] 69 15 }

  condition:
    any of them
}