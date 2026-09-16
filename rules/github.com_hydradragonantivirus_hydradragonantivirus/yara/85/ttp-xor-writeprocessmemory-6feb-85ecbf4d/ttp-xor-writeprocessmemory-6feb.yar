rule TTP_XOR_WriteProcessMemory_6feb {
  strings:
    $key_6feb = { 38 99 [2] 0a bb [2] 0c 8e [2] 22 8e [2] 1d 92 }

  condition:
    any of them
}