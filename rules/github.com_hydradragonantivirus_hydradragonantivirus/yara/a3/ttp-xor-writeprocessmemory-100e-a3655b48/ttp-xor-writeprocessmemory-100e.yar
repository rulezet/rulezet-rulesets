rule TTP_XOR_WriteProcessMemory_100e {
  strings:
    $key_100e = { 47 7c [2] 75 5e [2] 73 6b [2] 5d 6b [2] 62 77 }

  condition:
    any of them
}