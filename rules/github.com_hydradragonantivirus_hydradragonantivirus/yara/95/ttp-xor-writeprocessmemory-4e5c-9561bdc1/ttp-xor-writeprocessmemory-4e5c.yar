rule TTP_XOR_WriteProcessMemory_4e5c {
  strings:
    $key_4e5c = { 19 2e [2] 2b 0c [2] 2d 39 [2] 03 39 [2] 3c 25 }

  condition:
    any of them
}