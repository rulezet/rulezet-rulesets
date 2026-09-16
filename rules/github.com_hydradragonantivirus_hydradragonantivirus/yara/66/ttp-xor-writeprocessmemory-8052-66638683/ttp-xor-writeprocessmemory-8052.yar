rule TTP_XOR_WriteProcessMemory_8052 {
  strings:
    $key_8052 = { d7 20 [2] e5 02 [2] e3 37 [2] cd 37 [2] f2 2b }

  condition:
    any of them
}