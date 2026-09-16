rule TTP_XOR_WriteProcessMemory_4c2c {
  strings:
    $key_4c2c = { 1b 5e [2] 29 7c [2] 2f 49 [2] 01 49 [2] 3e 55 }

  condition:
    any of them
}