rule TTP_XOR_WriteProcessMemory_400f {
  strings:
    $key_400f = { 17 7d [2] 25 5f [2] 23 6a [2] 0d 6a [2] 32 76 }

  condition:
    any of them
}