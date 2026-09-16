rule TTP_XOR_WriteProcessMemory_4bfc {
  strings:
    $key_4bfc = { 1c 8e [2] 2e ac [2] 28 99 [2] 06 99 [2] 39 85 }

  condition:
    any of them
}