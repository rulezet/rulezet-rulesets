rule TTP_XOR_WriteProcessMemory_f0fc {
  strings:
    $key_f0fc = { a7 8e [2] 95 ac [2] 93 99 [2] bd 99 [2] 82 85 }

  condition:
    any of them
}