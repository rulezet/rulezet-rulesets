rule TTP_XOR_WriteProcessMemory_1f7c {
  strings:
    $key_1f7c = { 48 0e [2] 7a 2c [2] 7c 19 [2] 52 19 [2] 6d 05 }

  condition:
    any of them
}