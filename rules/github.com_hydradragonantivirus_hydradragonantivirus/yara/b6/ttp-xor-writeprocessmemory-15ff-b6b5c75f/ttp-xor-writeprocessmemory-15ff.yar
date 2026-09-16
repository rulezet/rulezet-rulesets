rule TTP_XOR_WriteProcessMemory_15ff {
  strings:
    $key_15ff = { 42 8d [2] 70 af [2] 76 9a [2] 58 9a [2] 67 86 }

  condition:
    any of them
}