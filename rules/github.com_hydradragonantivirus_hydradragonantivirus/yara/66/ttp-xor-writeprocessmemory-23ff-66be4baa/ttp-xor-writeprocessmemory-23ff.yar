rule TTP_XOR_WriteProcessMemory_23ff {
  strings:
    $key_23ff = { 74 8d [2] 46 af [2] 40 9a [2] 6e 9a [2] 51 86 }

  condition:
    any of them
}