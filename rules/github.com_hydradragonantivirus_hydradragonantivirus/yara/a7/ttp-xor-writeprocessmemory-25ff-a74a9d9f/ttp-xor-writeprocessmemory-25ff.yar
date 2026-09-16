rule TTP_XOR_WriteProcessMemory_25ff {
  strings:
    $key_25ff = { 72 8d [2] 40 af [2] 46 9a [2] 68 9a [2] 57 86 }

  condition:
    any of them
}