rule TTP_XOR_WriteProcessMemory_105e {
  strings:
    $key_105e = { 47 2c [2] 75 0e [2] 73 3b [2] 5d 3b [2] 62 27 }

  condition:
    any of them
}