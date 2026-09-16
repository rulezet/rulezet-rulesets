rule TTP_XOR_WriteProcessMemory_6bfc {
  strings:
    $key_6bfc = { 3c 8e [2] 0e ac [2] 08 99 [2] 26 99 [2] 19 85 }

  condition:
    any of them
}