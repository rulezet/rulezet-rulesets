rule TTP_XOR_WriteProcessMemory_7f7c {
  strings:
    $key_7f7c = { 28 0e [2] 1a 2c [2] 1c 19 [2] 32 19 [2] 0d 05 }

  condition:
    any of them
}