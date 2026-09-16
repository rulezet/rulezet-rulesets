rule TTP_XOR_WriteProcessMemory_fafc {
  strings:
    $key_fafc = { ad 8e [2] 9f ac [2] 99 99 [2] b7 99 [2] 88 85 }

  condition:
    any of them
}