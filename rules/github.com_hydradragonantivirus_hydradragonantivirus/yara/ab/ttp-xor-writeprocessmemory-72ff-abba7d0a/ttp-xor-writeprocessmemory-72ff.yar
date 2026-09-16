rule TTP_XOR_WriteProcessMemory_72ff {
  strings:
    $key_72ff = { 25 8d [2] 17 af [2] 11 9a [2] 3f 9a [2] 00 86 }

  condition:
    any of them
}