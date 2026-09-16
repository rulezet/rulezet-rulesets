rule TTP_XOR_WriteProcessMemory_492e {
  strings:
    $key_492e = { 1e 5c [2] 2c 7e [2] 2a 4b [2] 04 4b [2] 3b 57 }

  condition:
    any of them
}