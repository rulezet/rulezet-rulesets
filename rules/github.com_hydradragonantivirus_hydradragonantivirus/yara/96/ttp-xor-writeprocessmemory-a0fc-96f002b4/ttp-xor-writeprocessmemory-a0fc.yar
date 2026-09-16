rule TTP_XOR_WriteProcessMemory_a0fc {
  strings:
    $key_a0fc = { f7 8e [2] c5 ac [2] c3 99 [2] ed 99 [2] d2 85 }

  condition:
    any of them
}