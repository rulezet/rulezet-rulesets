rule TTP_XOR_WriteProcessMemory_a5fc {
  strings:
    $key_a5fc = { f2 8e [2] c0 ac [2] c6 99 [2] e8 99 [2] d7 85 }

  condition:
    any of them
}