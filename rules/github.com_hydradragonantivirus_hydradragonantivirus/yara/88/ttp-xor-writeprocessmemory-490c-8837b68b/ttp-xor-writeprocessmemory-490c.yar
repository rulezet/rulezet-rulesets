rule TTP_XOR_WriteProcessMemory_490c {
  strings:
    $key_490c = { 1e 7e [2] 2c 5c [2] 2a 69 [2] 04 69 [2] 3b 75 }

  condition:
    any of them
}