rule TTP_XOR_WriteProcessMemory_7e7e {
  strings:
    $key_7e7e = { 29 0c [2] 1b 2e [2] 1d 1b [2] 33 1b [2] 0c 07 }

  condition:
    any of them
}