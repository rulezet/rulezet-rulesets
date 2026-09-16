rule TTP_XOR_WriteProcessMemory_054b {
  strings:
    $key_054b = { 52 39 [2] 60 1b [2] 66 2e [2] 48 2e [2] 77 32 }

  condition:
    any of them
}