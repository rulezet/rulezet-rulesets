rule TTP_XOR_WriteProcessMemory_590c {
  strings:
    $key_590c = { 0e 7e [2] 3c 5c [2] 3a 69 [2] 14 69 [2] 2b 75 }

  condition:
    any of them
}