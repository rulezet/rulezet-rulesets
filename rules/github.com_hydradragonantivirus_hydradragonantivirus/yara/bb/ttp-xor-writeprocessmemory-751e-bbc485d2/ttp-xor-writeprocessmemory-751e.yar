rule TTP_XOR_WriteProcessMemory_751e {
  strings:
    $key_751e = { 22 6c [2] 10 4e [2] 16 7b [2] 38 7b [2] 07 67 }

  condition:
    any of them
}