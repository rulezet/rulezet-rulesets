rule TTP_XOR_WriteProcessMemory_7e6c {
  strings:
    $key_7e6c = { 29 1e [2] 1b 3c [2] 1d 09 [2] 33 09 [2] 0c 15 }

  condition:
    any of them
}