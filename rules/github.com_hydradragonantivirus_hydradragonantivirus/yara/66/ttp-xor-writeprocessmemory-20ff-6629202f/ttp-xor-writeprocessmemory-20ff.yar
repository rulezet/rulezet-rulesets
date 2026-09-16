rule TTP_XOR_WriteProcessMemory_20ff {
  strings:
    $key_20ff = { 77 8d [2] 45 af [2] 43 9a [2] 6d 9a [2] 52 86 }

  condition:
    any of them
}