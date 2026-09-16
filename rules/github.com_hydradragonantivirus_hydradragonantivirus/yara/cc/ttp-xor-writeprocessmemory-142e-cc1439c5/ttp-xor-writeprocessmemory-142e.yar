rule TTP_XOR_WriteProcessMemory_142e {
  strings:
    $key_142e = { 43 5c [2] 71 7e [2] 77 4b [2] 59 4b [2] 66 57 }

  condition:
    any of them
}