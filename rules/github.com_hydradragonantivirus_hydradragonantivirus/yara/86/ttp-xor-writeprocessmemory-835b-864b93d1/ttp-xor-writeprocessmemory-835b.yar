rule TTP_XOR_WriteProcessMemory_835b {
  strings:
    $key_835b = { d4 29 [2] e6 0b [2] e0 3e [2] ce 3e [2] f1 22 }

  condition:
    any of them
}