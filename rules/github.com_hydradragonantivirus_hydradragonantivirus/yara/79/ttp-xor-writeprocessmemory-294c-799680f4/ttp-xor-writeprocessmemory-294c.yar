rule TTP_XOR_WriteProcessMemory_294c {
  strings:
    $key_294c = { 7e 3e [2] 4c 1c [2] 4a 29 [2] 64 29 [2] 5b 35 }

  condition:
    any of them
}