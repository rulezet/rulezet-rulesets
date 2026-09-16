rule TTP_XOR_WriteProcessMemory_3e7c {
  strings:
    $key_3e7c = { 69 0e [2] 5b 2c [2] 5d 19 [2] 73 19 [2] 4c 05 }

  condition:
    any of them
}