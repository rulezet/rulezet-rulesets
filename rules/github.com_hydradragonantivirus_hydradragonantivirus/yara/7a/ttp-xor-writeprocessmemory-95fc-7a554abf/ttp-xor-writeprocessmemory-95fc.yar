rule TTP_XOR_WriteProcessMemory_95fc {
  strings:
    $key_95fc = { c2 8e [2] f0 ac [2] f6 99 [2] d8 99 [2] e7 85 }

  condition:
    any of them
}