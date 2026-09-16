rule TTP_XOR_WriteProcessMemory_5a7e {
  strings:
    $key_5a7e = { 0d 0c [2] 3f 2e [2] 39 1b [2] 17 1b [2] 28 07 }

  condition:
    any of them
}