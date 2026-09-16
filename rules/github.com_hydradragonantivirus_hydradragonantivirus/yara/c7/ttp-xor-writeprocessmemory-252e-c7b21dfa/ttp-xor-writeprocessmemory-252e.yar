rule TTP_XOR_WriteProcessMemory_252e {
  strings:
    $key_252e = { 72 5c [2] 40 7e [2] 46 4b [2] 68 4b [2] 57 57 }

  condition:
    any of them
}