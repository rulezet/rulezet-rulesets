rule TTP_XOR_WriteProcessMemory_492c {
  strings:
    $key_492c = { 1e 5e [2] 2c 7c [2] 2a 49 [2] 04 49 [2] 3b 55 }

  condition:
    any of them
}