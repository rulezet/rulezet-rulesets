rule TTP_XOR_WriteProcessMemory_666e {
  strings:
    $key_666e = { 31 1c [2] 03 3e [2] 05 0b [2] 2b 0b [2] 14 17 }

  condition:
    any of them
}