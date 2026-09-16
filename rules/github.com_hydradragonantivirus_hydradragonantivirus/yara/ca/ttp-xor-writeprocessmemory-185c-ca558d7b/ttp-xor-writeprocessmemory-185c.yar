rule TTP_XOR_WriteProcessMemory_185c {
  strings:
    $key_185c = { 4f 2e [2] 7d 0c [2] 7b 39 [2] 55 39 [2] 6a 25 }

  condition:
    any of them
}