rule TTP_XOR_WriteProcessMemory_51ff {
  strings:
    $key_51ff = { 06 8d [2] 34 af [2] 32 9a [2] 1c 9a [2] 23 86 }

  condition:
    any of them
}