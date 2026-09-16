rule TTP_XOR_WriteProcessMemory_481c {
  strings:
    $key_481c = { 1f 6e [2] 2d 4c [2] 2b 79 [2] 05 79 [2] 3a 65 }

  condition:
    any of them
}