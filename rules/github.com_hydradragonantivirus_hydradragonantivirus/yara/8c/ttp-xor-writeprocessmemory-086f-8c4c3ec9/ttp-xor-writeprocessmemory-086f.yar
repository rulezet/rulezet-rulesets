rule TTP_XOR_WriteProcessMemory_086f {
  strings:
    $key_086f = { 5f 1d [2] 6d 3f [2] 6b 0a [2] 45 0a [2] 7a 16 }

  condition:
    any of them
}