rule TTP_XOR_WriteProcessMemory_106e {
  strings:
    $key_106e = { 47 1c [2] 75 3e [2] 73 0b [2] 5d 0b [2] 62 17 }

  condition:
    any of them
}