rule TTP_XOR_WriteProcessMemory_236e {
  strings:
    $key_236e = { 74 1c [2] 46 3e [2] 40 0b [2] 6e 0b [2] 51 17 }

  condition:
    any of them
}