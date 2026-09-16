rule TTP_XOR_WriteProcessMemory_500f {
  strings:
    $key_500f = { 07 7d [2] 35 5f [2] 33 6a [2] 1d 6a [2] 22 76 }

  condition:
    any of them
}