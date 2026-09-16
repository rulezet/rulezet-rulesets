rule TTP_XOR_WriteProcessMemory_19ff {
  strings:
    $key_19ff = { 4e 8d [2] 7c af [2] 7a 9a [2] 54 9a [2] 6b 86 }

  condition:
    any of them
}