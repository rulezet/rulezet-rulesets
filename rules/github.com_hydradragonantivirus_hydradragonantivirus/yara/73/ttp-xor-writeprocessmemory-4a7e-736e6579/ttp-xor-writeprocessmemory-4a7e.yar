rule TTP_XOR_WriteProcessMemory_4a7e {
  strings:
    $key_4a7e = { 1d 0c [2] 2f 2e [2] 29 1b [2] 07 1b [2] 38 07 }

  condition:
    any of them
}