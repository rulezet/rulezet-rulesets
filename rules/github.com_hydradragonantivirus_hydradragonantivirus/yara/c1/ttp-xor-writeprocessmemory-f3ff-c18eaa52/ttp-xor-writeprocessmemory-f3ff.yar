rule TTP_XOR_WriteProcessMemory_f3ff {
  strings:
    $key_f3ff = { a4 8d [2] 96 af [2] 90 9a [2] be 9a [2] 81 86 }

  condition:
    any of them
}