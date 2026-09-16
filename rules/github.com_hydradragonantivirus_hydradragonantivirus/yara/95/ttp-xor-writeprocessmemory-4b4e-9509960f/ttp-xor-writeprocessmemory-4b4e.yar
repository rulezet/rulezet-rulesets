rule TTP_XOR_WriteProcessMemory_4b4e {
  strings:
    $key_4b4e = { 1c 3c [2] 2e 1e [2] 28 2b [2] 06 2b [2] 39 37 }

  condition:
    any of them
}