rule TTP_XOR_WriteProcessMemory_246c {
  strings:
    $key_246c = { 73 1e [2] 41 3c [2] 47 09 [2] 69 09 [2] 56 15 }

  condition:
    any of them
}