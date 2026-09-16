rule TTP_XOR_WriteProcessMemory_83fc {
  strings:
    $key_83fc = { d4 8e [2] e6 ac [2] e0 99 [2] ce 99 [2] f1 85 }

  condition:
    any of them
}