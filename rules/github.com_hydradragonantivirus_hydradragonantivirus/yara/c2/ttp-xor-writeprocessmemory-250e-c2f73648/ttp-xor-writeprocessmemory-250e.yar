rule TTP_XOR_WriteProcessMemory_250e {
  strings:
    $key_250e = { 72 7c [2] 40 5e [2] 46 6b [2] 68 6b [2] 57 77 }

  condition:
    any of them
}