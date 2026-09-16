rule TTP_XOR_WriteProcessMemory_4e3c {
  strings:
    $key_4e3c = { 19 4e [2] 2b 6c [2] 2d 59 [2] 03 59 [2] 3c 45 }

  condition:
    any of them
}