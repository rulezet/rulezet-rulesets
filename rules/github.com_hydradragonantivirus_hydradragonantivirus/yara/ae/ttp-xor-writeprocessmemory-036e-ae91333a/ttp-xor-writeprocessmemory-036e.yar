rule TTP_XOR_WriteProcessMemory_036e {
  strings:
    $key_036e = { 54 1c [2] 66 3e [2] 60 0b [2] 4e 0b [2] 71 17 }

  condition:
    any of them
}