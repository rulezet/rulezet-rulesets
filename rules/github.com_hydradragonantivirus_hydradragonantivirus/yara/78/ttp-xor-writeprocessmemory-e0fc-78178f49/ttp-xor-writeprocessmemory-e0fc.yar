rule TTP_XOR_WriteProcessMemory_e0fc {
  strings:
    $key_e0fc = { b7 8e [2] 85 ac [2] 83 99 [2] ad 99 [2] 92 85 }

  condition:
    any of them
}