rule TTP_XOR_WriteProcessMemory_b0fc {
  strings:
    $key_b0fc = { e7 8e [2] d5 ac [2] d3 99 [2] fd 99 [2] c2 85 }

  condition:
    any of them
}