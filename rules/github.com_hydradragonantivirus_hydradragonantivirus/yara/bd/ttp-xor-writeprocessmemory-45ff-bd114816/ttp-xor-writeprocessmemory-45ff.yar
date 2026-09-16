rule TTP_XOR_WriteProcessMemory_45ff {
  strings:
    $key_45ff = { 12 8d [2] 20 af [2] 26 9a [2] 08 9a [2] 37 86 }

  condition:
    any of them
}