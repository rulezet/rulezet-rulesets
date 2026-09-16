rule TTP_XOR_WriteProcessMemory_601c {
  strings:
    $key_601c = { 37 6e [2] 05 4c [2] 03 79 [2] 2d 79 [2] 12 65 }

  condition:
    any of them
}