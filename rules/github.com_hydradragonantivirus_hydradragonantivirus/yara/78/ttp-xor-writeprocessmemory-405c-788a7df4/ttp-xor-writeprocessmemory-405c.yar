rule TTP_XOR_WriteProcessMemory_405c {
  strings:
    $key_405c = { 17 2e [2] 25 0c [2] 23 39 [2] 0d 39 [2] 32 25 }

  condition:
    any of them
}