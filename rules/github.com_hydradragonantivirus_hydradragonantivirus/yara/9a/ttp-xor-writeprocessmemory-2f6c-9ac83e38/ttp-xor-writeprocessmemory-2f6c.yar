rule TTP_XOR_WriteProcessMemory_2f6c {
  strings:
    $key_2f6c = { 78 1e [2] 4a 3c [2] 4c 09 [2] 62 09 [2] 5d 15 }

  condition:
    any of them
}