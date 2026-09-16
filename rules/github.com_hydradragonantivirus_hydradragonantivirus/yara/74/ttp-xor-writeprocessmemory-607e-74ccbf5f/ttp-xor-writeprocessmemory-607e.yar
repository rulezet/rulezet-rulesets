rule TTP_XOR_WriteProcessMemory_607e {
  strings:
    $key_607e = { 37 0c [2] 05 2e [2] 03 1b [2] 2d 1b [2] 12 07 }

  condition:
    any of them
}