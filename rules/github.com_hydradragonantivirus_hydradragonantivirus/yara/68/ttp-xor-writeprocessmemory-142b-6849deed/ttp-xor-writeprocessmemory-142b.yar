rule TTP_XOR_WriteProcessMemory_142b {
  strings:
    $key_142b = { 43 59 [2] 71 7b [2] 77 4e [2] 59 4e [2] 66 52 }

  condition:
    any of them
}