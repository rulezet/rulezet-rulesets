rule TTP_XOR_WriteProcessMemory_717e {
  strings:
    $key_717e = { 26 0c [2] 14 2e [2] 12 1b [2] 3c 1b [2] 03 07 }

  condition:
    any of them
}