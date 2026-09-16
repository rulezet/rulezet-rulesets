rule TTP_XOR_WriteProcessMemory_410c {
  strings:
    $key_410c = { 16 7e [2] 24 5c [2] 22 69 [2] 0c 69 [2] 33 75 }

  condition:
    any of them
}