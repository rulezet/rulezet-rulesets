rule TTP_XOR_WriteProcessMemory_107e {
  strings:
    $key_107e = { 47 0c [2] 75 2e [2] 73 1b [2] 5d 1b [2] 62 07 }

  condition:
    any of them
}