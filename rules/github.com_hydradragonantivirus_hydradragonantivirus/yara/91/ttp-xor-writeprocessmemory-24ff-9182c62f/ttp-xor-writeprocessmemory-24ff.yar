rule TTP_XOR_WriteProcessMemory_24ff {
  strings:
    $key_24ff = { 73 8d [2] 41 af [2] 47 9a [2] 69 9a [2] 56 86 }

  condition:
    any of them
}