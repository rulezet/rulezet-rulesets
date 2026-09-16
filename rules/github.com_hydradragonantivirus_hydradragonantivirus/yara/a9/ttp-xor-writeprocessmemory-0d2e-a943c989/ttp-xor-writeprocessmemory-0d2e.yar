rule TTP_XOR_WriteProcessMemory_0d2e {
  strings:
    $key_0d2e = { 5a 5c [2] 68 7e [2] 6e 4b [2] 40 4b [2] 7f 57 }

  condition:
    any of them
}