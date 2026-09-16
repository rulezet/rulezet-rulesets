rule TTP_XOR_WriteProcessMemory_5c5c {
  strings:
    $key_5c5c = { 0b 2e [2] 39 0c [2] 3f 39 [2] 11 39 [2] 2e 25 }

  condition:
    any of them
}