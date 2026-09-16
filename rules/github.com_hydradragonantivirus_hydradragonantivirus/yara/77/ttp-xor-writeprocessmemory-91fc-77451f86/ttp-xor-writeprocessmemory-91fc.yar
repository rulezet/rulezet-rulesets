rule TTP_XOR_WriteProcessMemory_91fc {
  strings:
    $key_91fc = { c6 8e [2] f4 ac [2] f2 99 [2] dc 99 [2] e3 85 }

  condition:
    any of them
}