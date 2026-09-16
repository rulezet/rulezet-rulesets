rule TTP_XOR_WriteProcessMemory_5d7e {
  strings:
    $key_5d7e = { 0a 0c [2] 38 2e [2] 3e 1b [2] 10 1b [2] 2f 07 }

  condition:
    any of them
}