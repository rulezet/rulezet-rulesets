rule TTP_XOR_WriteProcessMemory_e4fc {
  strings:
    $key_e4fc = { b3 8e [2] 81 ac [2] 87 99 [2] a9 99 [2] 96 85 }

  condition:
    any of them
}