rule TTP_XOR_WriteProcessMemory_3b7c {
  strings:
    $key_3b7c = { 6c 0e [2] 5e 2c [2] 58 19 [2] 76 19 [2] 49 05 }

  condition:
    any of them
}