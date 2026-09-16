rule TTP_XOR_WriteProcessMemory_86fc {
  strings:
    $key_86fc = { d1 8e [2] e3 ac [2] e5 99 [2] cb 99 [2] f4 85 }

  condition:
    any of them
}