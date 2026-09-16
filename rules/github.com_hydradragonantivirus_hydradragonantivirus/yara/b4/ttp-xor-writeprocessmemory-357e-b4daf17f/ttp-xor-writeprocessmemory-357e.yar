rule TTP_XOR_WriteProcessMemory_357e {
  strings:
    $key_357e = { 62 0c [2] 50 2e [2] 56 1b [2] 78 1b [2] 47 07 }

  condition:
    any of them
}