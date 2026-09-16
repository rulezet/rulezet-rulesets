rule TTP_XOR_WriteProcessMemory_4efc {
  strings:
    $key_4efc = { 19 8e [2] 2b ac [2] 2d 99 [2] 03 99 [2] 3c 85 }

  condition:
    any of them
}