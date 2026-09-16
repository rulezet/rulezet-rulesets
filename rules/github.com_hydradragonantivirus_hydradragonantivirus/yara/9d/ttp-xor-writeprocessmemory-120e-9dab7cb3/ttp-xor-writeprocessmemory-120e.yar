rule TTP_XOR_WriteProcessMemory_120e {
  strings:
    $key_120e = { 45 7c [2] 77 5e [2] 71 6b [2] 5f 6b [2] 60 77 }

  condition:
    any of them
}