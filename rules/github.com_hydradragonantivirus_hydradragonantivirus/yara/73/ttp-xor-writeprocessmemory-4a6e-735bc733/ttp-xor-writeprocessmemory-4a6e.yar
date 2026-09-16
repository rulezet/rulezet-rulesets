rule TTP_XOR_WriteProcessMemory_4a6e {
  strings:
    $key_4a6e = { 1d 1c [2] 2f 3e [2] 29 0b [2] 07 0b [2] 38 17 }

  condition:
    any of them
}