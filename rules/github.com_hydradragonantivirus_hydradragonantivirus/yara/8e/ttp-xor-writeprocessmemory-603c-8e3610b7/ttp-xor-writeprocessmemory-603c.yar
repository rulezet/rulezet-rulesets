rule TTP_XOR_WriteProcessMemory_603c {
  strings:
    $key_603c = { 37 4e [2] 05 6c [2] 03 59 [2] 2d 59 [2] 12 45 }

  condition:
    any of them
}