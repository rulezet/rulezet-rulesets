rule TTP_XOR_WriteProcessMemory_3ffc {
  strings:
    $key_3ffc = { 68 8e [2] 5a ac [2] 5c 99 [2] 72 99 [2] 4d 85 }

  condition:
    any of them
}