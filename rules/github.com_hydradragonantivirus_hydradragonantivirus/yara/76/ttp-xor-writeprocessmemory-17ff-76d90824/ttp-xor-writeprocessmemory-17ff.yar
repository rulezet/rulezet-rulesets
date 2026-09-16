rule TTP_XOR_WriteProcessMemory_17ff {
  strings:
    $key_17ff = { 40 8d [2] 72 af [2] 74 9a [2] 5a 9a [2] 65 86 }

  condition:
    any of them
}