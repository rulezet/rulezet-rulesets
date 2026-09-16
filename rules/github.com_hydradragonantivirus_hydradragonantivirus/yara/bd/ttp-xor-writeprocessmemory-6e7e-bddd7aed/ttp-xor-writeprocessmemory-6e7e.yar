rule TTP_XOR_WriteProcessMemory_6e7e {
  strings:
    $key_6e7e = { 39 0c [2] 0b 2e [2] 0d 1b [2] 23 1b [2] 1c 07 }

  condition:
    any of them
}