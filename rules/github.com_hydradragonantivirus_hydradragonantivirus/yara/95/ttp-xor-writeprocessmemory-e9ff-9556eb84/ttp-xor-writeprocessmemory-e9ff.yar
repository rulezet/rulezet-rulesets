rule TTP_XOR_WriteProcessMemory_e9ff {
  strings:
    $key_e9ff = { be 8d [2] 8c af [2] 8a 9a [2] a4 9a [2] 9b 86 }

  condition:
    any of them
}