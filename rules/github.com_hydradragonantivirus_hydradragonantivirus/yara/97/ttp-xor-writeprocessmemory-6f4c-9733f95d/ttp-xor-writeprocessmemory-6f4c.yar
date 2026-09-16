rule TTP_XOR_WriteProcessMemory_6f4c {
  strings:
    $key_6f4c = { 38 3e [2] 0a 1c [2] 0c 29 [2] 22 29 [2] 1d 35 }

  condition:
    any of them
}