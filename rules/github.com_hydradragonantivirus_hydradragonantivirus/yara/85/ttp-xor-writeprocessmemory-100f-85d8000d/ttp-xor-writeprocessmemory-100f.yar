rule TTP_XOR_WriteProcessMemory_100f {
  strings:
    $key_100f = { 47 7d [2] 75 5f [2] 73 6a [2] 5d 6a [2] 62 76 }

  condition:
    any of them
}