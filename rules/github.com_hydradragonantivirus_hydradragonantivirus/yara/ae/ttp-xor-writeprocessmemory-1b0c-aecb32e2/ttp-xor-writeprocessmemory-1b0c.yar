rule TTP_XOR_WriteProcessMemory_1b0c {
  strings:
    $key_1b0c = { 4c 7e [2] 7e 5c [2] 78 69 [2] 56 69 [2] 69 75 }

  condition:
    any of them
}