rule TTP_XOR_WriteProcessMemory_052b {
  strings:
    $key_052b = { 52 59 [2] 60 7b [2] 66 4e [2] 48 4e [2] 77 52 }

  condition:
    any of them
}