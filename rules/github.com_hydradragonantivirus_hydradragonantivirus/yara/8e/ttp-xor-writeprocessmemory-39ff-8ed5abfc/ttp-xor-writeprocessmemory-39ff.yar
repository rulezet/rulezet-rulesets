rule TTP_XOR_WriteProcessMemory_39ff {
  strings:
    $key_39ff = { 6e 8d [2] 5c af [2] 5a 9a [2] 74 9a [2] 4b 86 }

  condition:
    any of them
}