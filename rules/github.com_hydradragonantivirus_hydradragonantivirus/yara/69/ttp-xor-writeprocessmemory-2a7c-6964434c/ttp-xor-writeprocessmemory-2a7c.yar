rule TTP_XOR_WriteProcessMemory_2a7c {
  strings:
    $key_2a7c = { 7d 0e [2] 4f 2c [2] 49 19 [2] 67 19 [2] 58 05 }

  condition:
    any of them
}