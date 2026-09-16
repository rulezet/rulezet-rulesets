rule TTP_XOR_WriteProcessMemory_180f {
  strings:
    $key_180f = { 4f 7d [2] 7d 5f [2] 7b 6a [2] 55 6a [2] 6a 76 }

  condition:
    any of them
}