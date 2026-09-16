rule TTP_XOR_WriteProcessMemory_6d2c {
  strings:
    $key_6d2c = { 3a 5e [2] 08 7c [2] 0e 49 [2] 20 49 [2] 1f 55 }

  condition:
    any of them
}