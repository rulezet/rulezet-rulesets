rule TTP_XOR_WriteProcessMemory_a7fc {
  strings:
    $key_a7fc = { f0 8e [2] c2 ac [2] c4 99 [2] ea 99 [2] d5 85 }

  condition:
    any of them
}