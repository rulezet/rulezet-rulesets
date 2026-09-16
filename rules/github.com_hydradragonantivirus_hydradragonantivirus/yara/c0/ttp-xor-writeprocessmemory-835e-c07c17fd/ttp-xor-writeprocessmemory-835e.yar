rule TTP_XOR_WriteProcessMemory_835e {
  strings:
    $key_835e = { d4 2c [2] e6 0e [2] e0 3b [2] ce 3b [2] f1 27 }

  condition:
    any of them
}