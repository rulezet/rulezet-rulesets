rule TTP_XOR_WriteProcessMemory_503c {
  strings:
    $key_503c = { 07 4e [2] 35 6c [2] 33 59 [2] 1d 59 [2] 22 45 }

  condition:
    any of them
}