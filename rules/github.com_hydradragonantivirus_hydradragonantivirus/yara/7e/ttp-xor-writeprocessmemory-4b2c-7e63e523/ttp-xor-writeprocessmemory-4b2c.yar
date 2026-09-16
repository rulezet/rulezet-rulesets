rule TTP_XOR_WriteProcessMemory_4b2c {
  strings:
    $key_4b2c = { 1c 5e [2] 2e 7c [2] 28 49 [2] 06 49 [2] 39 55 }

  condition:
    any of them
}