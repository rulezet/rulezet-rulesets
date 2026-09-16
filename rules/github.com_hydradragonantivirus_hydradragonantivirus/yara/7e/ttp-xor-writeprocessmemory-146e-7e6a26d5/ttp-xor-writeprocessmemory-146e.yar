rule TTP_XOR_WriteProcessMemory_146e {
  strings:
    $key_146e = { 43 1c [2] 71 3e [2] 77 0b [2] 59 0b [2] 66 17 }

  condition:
    any of them
}