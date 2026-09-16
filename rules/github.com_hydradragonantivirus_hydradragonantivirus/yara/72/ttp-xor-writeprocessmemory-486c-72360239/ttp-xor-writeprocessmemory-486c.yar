rule TTP_XOR_WriteProcessMemory_486c {
  strings:
    $key_486c = { 1f 1e [2] 2d 3c [2] 2b 09 [2] 05 09 [2] 3a 15 }

  condition:
    any of them
}