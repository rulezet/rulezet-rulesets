rule TTP_XOR_WriteProcessMemory_480f {
  strings:
    $key_480f = { 1f 7d [2] 2d 5f [2] 2b 6a [2] 05 6a [2] 3a 76 }

  condition:
    any of them
}