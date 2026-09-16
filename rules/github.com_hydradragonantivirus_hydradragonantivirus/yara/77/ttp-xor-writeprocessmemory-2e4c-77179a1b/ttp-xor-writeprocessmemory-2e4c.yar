rule TTP_XOR_WriteProcessMemory_2e4c {
  strings:
    $key_2e4c = { 79 3e [2] 4b 1c [2] 4d 29 [2] 63 29 [2] 5c 35 }

  condition:
    any of them
}