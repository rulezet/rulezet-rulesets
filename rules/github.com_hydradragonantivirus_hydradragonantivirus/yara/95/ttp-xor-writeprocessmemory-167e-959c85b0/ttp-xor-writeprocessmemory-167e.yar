rule TTP_XOR_WriteProcessMemory_167e {
  strings:
    $key_167e = { 41 0c [2] 73 2e [2] 75 1b [2] 5b 1b [2] 64 07 }

  condition:
    any of them
}