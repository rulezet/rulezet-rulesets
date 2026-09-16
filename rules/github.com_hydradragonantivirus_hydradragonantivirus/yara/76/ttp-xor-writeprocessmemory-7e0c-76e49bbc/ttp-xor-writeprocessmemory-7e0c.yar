rule TTP_XOR_WriteProcessMemory_7e0c {
  strings:
    $key_7e0c = { 29 7e [2] 1b 5c [2] 1d 69 [2] 33 69 [2] 0c 75 }

  condition:
    any of them
}