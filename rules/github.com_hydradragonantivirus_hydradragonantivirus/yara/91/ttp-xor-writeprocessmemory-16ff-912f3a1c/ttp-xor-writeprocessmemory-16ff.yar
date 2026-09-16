rule TTP_XOR_WriteProcessMemory_16ff {
  strings:
    $key_16ff = { 41 8d [2] 73 af [2] 75 9a [2] 5b 9a [2] 64 86 }

  condition:
    any of them
}