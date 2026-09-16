rule TTP_XOR_WriteProcessMemory_2e2c {
  strings:
    $key_2e2c = { 79 5e [2] 4b 7c [2] 4d 49 [2] 63 49 [2] 5c 55 }

  condition:
    any of them
}