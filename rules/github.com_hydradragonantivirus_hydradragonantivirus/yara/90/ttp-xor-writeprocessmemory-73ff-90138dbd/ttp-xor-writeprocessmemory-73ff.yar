rule TTP_XOR_WriteProcessMemory_73ff {
  strings:
    $key_73ff = { 24 8d [2] 16 af [2] 10 9a [2] 3e 9a [2] 01 86 }

  condition:
    any of them
}