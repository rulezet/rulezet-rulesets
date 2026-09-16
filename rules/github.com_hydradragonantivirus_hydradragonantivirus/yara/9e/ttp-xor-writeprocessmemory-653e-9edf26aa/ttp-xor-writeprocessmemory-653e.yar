rule TTP_XOR_WriteProcessMemory_653e {
  strings:
    $key_653e = { 32 4c [2] 00 6e [2] 06 5b [2] 28 5b [2] 17 47 }

  condition:
    any of them
}