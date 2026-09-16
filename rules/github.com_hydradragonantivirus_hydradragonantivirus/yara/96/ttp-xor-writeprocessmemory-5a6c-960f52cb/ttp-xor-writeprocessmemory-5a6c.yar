rule TTP_XOR_WriteProcessMemory_5a6c {
  strings:
    $key_5a6c = { 0d 1e [2] 3f 3c [2] 39 09 [2] 17 09 [2] 28 15 }

  condition:
    any of them
}