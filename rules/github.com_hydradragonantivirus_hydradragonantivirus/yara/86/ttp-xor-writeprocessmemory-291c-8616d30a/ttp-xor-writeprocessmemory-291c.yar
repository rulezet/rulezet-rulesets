rule TTP_XOR_WriteProcessMemory_291c {
  strings:
    $key_291c = { 7e 6e [2] 4c 4c [2] 4a 79 [2] 64 79 [2] 5b 65 }

  condition:
    any of them
}