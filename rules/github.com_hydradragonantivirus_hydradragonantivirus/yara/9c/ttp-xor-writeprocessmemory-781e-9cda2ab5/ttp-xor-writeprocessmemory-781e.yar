rule TTP_XOR_WriteProcessMemory_781e {
  strings:
    $key_781e = { 2f 6c [2] 1d 4e [2] 1b 7b [2] 35 7b [2] 0a 67 }

  condition:
    any of them
}