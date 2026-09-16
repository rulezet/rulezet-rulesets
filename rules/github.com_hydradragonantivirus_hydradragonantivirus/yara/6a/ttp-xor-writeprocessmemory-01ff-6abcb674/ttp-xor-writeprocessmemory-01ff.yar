rule TTP_XOR_WriteProcessMemory_01ff {
  strings:
    $key_01ff = { 56 8d [2] 64 af [2] 62 9a [2] 4c 9a [2] 73 86 }

  condition:
    any of them
}