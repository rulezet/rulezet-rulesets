rule TTP_XOR_WriteProcessMemory_92fc {
  strings:
    $key_92fc = { c5 8e [2] f7 ac [2] f1 99 [2] df 99 [2] e0 85 }

  condition:
    any of them
}