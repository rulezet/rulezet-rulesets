rule TTP_XOR_WriteProcessMemory_094c {
  strings:
    $key_094c = { 5e 3e [2] 6c 1c [2] 6a 29 [2] 44 29 [2] 7b 35 }

  condition:
    any of them
}