rule TTP_XOR_WriteProcessMemory_3f5c {
  strings:
    $key_3f5c = { 68 2e [2] 5a 0c [2] 5c 39 [2] 72 39 [2] 4d 25 }

  condition:
    any of them
}