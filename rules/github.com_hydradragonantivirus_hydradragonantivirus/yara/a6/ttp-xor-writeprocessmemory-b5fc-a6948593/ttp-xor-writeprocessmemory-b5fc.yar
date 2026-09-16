rule TTP_XOR_WriteProcessMemory_b5fc {
  strings:
    $key_b5fc = { e2 8e [2] d0 ac [2] d6 99 [2] f8 99 [2] c7 85 }

  condition:
    any of them
}