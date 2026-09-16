rule TTP_XOR_WriteProcessMemory_206c {
  strings:
    $key_206c = { 77 1e [2] 45 3c [2] 43 09 [2] 6d 09 [2] 52 15 }

  condition:
    any of them
}