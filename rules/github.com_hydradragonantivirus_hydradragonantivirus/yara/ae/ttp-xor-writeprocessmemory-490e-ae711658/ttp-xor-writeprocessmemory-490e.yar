rule TTP_XOR_WriteProcessMemory_490e {
  strings:
    $key_490e = { 1e 7c [2] 2c 5e [2] 2a 6b [2] 04 6b [2] 3b 77 }

  condition:
    any of them
}