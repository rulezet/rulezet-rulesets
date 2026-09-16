rule TTP_XOR_WriteProcessMemory_122e {
  strings:
    $key_122e = { 45 5c [2] 77 7e [2] 71 4b [2] 5f 4b [2] 60 57 }

  condition:
    any of them
}