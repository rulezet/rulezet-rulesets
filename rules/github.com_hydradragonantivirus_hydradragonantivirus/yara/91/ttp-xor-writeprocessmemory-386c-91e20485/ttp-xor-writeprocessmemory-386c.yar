rule TTP_XOR_WriteProcessMemory_386c {
  strings:
    $key_386c = { 6f 1e [2] 5d 3c [2] 5b 09 [2] 75 09 [2] 4a 15 }

  condition:
    any of them
}