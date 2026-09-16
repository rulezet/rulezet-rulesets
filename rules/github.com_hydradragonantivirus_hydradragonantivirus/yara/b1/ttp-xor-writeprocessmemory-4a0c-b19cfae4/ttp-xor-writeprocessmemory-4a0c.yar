rule TTP_XOR_WriteProcessMemory_4a0c {
  strings:
    $key_4a0c = { 1d 7e [2] 2f 5c [2] 29 69 [2] 07 69 [2] 38 75 }

  condition:
    any of them
}