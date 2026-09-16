rule TTP_XOR_WriteProcessMemory_646c {
  strings:
    $key_646c = { 33 1e [2] 01 3c [2] 07 09 [2] 29 09 [2] 16 15 }

  condition:
    any of them
}