rule TTP_XOR_WriteProcessMemory_262e {
  strings:
    $key_262e = { 71 5c [2] 43 7e [2] 45 4b [2] 6b 4b [2] 54 57 }

  condition:
    any of them
}