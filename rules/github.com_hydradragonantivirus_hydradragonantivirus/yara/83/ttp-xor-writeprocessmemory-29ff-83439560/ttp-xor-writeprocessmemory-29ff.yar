rule TTP_XOR_WriteProcessMemory_29ff {
  strings:
    $key_29ff = { 7e 8d [2] 4c af [2] 4a 9a [2] 64 9a [2] 5b 86 }

  condition:
    any of them
}