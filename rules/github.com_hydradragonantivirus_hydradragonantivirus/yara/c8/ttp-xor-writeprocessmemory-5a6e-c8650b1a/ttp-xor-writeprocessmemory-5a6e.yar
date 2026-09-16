rule TTP_XOR_WriteProcessMemory_5a6e {
  strings:
    $key_5a6e = { 0d 1c [2] 3f 3e [2] 39 0b [2] 17 0b [2] 28 17 }

  condition:
    any of them
}