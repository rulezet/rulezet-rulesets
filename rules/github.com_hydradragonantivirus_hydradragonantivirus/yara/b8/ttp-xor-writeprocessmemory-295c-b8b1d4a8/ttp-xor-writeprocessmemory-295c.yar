rule TTP_XOR_WriteProcessMemory_295c {
  strings:
    $key_295c = { 7e 2e [2] 4c 0c [2] 4a 39 [2] 64 39 [2] 5b 25 }

  condition:
    any of them
}