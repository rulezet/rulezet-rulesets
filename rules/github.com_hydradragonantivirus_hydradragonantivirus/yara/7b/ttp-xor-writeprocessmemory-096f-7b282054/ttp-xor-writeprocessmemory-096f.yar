rule TTP_XOR_WriteProcessMemory_096f {
  strings:
    $key_096f = { 5e 1d [2] 6c 3f [2] 6a 0a [2] 44 0a [2] 7b 16 }

  condition:
    any of them
}