rule TTP_XOR_WriteProcessMemory_721e {
  strings:
    $key_721e = { 25 6c [2] 17 4e [2] 11 7b [2] 3f 7b [2] 00 67 }

  condition:
    any of them
}