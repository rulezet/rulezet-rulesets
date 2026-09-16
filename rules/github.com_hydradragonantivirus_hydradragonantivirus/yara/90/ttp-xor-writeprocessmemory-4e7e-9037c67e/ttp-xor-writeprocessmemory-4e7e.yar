rule TTP_XOR_WriteProcessMemory_4e7e {
  strings:
    $key_4e7e = { 19 0c [2] 2b 2e [2] 2d 1b [2] 03 1b [2] 3c 07 }

  condition:
    any of them
}