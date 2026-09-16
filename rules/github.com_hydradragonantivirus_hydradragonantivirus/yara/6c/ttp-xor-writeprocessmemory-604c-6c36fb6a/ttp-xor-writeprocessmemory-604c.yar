rule TTP_XOR_WriteProcessMemory_604c {
  strings:
    $key_604c = { 37 3e [2] 05 1c [2] 03 29 [2] 2d 29 [2] 12 35 }

  condition:
    any of them
}