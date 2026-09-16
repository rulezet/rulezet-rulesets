rule TTP_XOR_WriteProcessMemory_127b {
  strings:
    $key_127b = { 45 09 [2] 77 2b [2] 71 1e [2] 5f 1e [2] 60 02 }

  condition:
    any of them
}