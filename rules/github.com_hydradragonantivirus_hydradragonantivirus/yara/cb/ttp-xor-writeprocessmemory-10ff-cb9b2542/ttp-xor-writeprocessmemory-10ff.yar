rule TTP_XOR_WriteProcessMemory_10ff {
  strings:
    $key_10ff = { 47 8d [2] 75 af [2] 73 9a [2] 5d 9a [2] 62 86 }

  condition:
    any of them
}