rule TTP_XOR_WriteProcessMemory_e1fc {
  strings:
    $key_e1fc = { b6 8e [2] 84 ac [2] 82 99 [2] ac 99 [2] 93 85 }

  condition:
    any of them
}