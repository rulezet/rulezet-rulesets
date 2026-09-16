rule TTP_XOR_WriteProcessMemory_2f7c {
  strings:
    $key_2f7c = { 78 0e [2] 4a 2c [2] 4c 19 [2] 62 19 [2] 5d 05 }

  condition:
    any of them
}