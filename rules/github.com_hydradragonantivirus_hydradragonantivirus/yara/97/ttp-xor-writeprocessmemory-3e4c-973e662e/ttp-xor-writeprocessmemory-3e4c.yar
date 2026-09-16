rule TTP_XOR_WriteProcessMemory_3e4c {
  strings:
    $key_3e4c = { 69 3e [2] 5b 1c [2] 5d 29 [2] 73 29 [2] 4c 35 }

  condition:
    any of them
}