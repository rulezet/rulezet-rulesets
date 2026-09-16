rule TTP_XOR_WriteProcessMemory_7f2c {
  strings:
    $key_7f2c = { 28 5e [2] 1a 7c [2] 1c 49 [2] 32 49 [2] 0d 55 }

  condition:
    any of them
}