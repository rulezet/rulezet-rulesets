rule TTP_XOR_WriteProcessMemory_1e2c {
  strings:
    $key_1e2c = { 49 5e [2] 7b 7c [2] 7d 49 [2] 53 49 [2] 6c 55 }

  condition:
    any of them
}