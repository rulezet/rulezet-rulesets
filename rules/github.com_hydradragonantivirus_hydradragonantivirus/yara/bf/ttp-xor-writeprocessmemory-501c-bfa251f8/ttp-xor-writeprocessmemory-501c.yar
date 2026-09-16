rule TTP_XOR_WriteProcessMemory_501c {
  strings:
    $key_501c = { 07 6e [2] 35 4c [2] 33 79 [2] 1d 79 [2] 22 65 }

  condition:
    any of them
}