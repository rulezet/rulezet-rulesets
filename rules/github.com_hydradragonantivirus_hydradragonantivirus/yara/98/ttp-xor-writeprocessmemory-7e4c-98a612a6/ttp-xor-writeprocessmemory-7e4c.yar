rule TTP_XOR_WriteProcessMemory_7e4c {
  strings:
    $key_7e4c = { 29 3e [2] 1b 1c [2] 1d 29 [2] 33 29 [2] 0c 35 }

  condition:
    any of them
}