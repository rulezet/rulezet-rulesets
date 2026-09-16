rule TTP_XOR_WriteProcessMemory_251e {
  strings:
    $key_251e = { 72 6c [2] 40 4e [2] 46 7b [2] 68 7b [2] 57 67 }

  condition:
    any of them
}