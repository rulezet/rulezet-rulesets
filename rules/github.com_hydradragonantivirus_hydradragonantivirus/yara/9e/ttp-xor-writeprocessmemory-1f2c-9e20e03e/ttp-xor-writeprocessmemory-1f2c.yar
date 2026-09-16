rule TTP_XOR_WriteProcessMemory_1f2c {
  strings:
    $key_1f2c = { 48 5e [2] 7a 7c [2] 7c 49 [2] 52 49 [2] 6d 55 }

  condition:
    any of them
}