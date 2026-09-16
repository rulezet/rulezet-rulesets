rule TTP_XOR_WriteProcessMemory_96ff {
  strings:
    $key_96ff = { c1 8d [2] f3 af [2] f5 9a [2] db 9a [2] e4 86 }

  condition:
    any of them
}