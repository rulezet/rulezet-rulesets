rule TTP_XOR_WriteProcessMemory_697c {
  strings:
    $key_697c = { 3e 0e [2] 0c 2c [2] 0a 19 [2] 24 19 [2] 1b 05 }

  condition:
    any of them
}