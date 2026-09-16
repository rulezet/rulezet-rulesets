rule TTP_XOR_WriteProcessMemory_2a6e {
  strings:
    $key_2a6e = { 7d 1c [2] 4f 3e [2] 49 0b [2] 67 0b [2] 58 17 }

  condition:
    any of them
}