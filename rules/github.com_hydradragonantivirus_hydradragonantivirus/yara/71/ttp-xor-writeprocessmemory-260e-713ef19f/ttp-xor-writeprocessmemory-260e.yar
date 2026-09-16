rule TTP_XOR_WriteProcessMemory_260e {
  strings:
    $key_260e = { 71 7c [2] 43 5e [2] 45 6b [2] 6b 6b [2] 54 77 }

  condition:
    any of them
}