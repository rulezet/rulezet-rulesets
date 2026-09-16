rule TTP_XOR_WriteProcessMemory_150e {
  strings:
    $key_150e = { 42 7c [2] 70 5e [2] 76 6b [2] 58 6b [2] 67 77 }

  condition:
    any of them
}