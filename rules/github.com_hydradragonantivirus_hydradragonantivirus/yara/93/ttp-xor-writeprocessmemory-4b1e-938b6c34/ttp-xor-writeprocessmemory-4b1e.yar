rule TTP_XOR_WriteProcessMemory_4b1e {
  strings:
    $key_4b1e = { 1c 6c [2] 2e 4e [2] 28 7b [2] 06 7b [2] 39 67 }

  condition:
    any of them
}