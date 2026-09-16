rule TTP_XOR_WriteProcessMemory_2a6c {
  strings:
    $key_2a6c = { 7d 1e [2] 4f 3c [2] 49 09 [2] 67 09 [2] 58 15 }

  condition:
    any of them
}