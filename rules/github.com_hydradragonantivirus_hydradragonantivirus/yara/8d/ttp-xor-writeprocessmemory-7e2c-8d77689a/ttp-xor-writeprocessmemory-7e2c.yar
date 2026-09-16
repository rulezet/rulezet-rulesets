rule TTP_XOR_WriteProcessMemory_7e2c {
  strings:
    $key_7e2c = { 29 5e [2] 1b 7c [2] 1d 49 [2] 33 49 [2] 0c 55 }

  condition:
    any of them
}