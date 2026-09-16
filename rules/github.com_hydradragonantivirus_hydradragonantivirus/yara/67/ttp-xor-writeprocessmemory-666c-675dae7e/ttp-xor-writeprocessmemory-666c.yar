rule TTP_XOR_WriteProcessMemory_666c {
  strings:
    $key_666c = { 31 1e [2] 03 3c [2] 05 09 [2] 2b 09 [2] 14 15 }

  condition:
    any of them
}