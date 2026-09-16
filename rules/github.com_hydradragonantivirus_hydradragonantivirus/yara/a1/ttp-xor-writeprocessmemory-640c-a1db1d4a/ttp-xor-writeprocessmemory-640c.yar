rule TTP_XOR_WriteProcessMemory_640c {
  strings:
    $key_640c = { 33 7e [2] 01 5c [2] 07 69 [2] 29 69 [2] 16 75 }

  condition:
    any of them
}