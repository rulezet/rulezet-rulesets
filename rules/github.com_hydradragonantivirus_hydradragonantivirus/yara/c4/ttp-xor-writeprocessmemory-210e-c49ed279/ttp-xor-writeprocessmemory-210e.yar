rule TTP_XOR_WriteProcessMemory_210e {
  strings:
    $key_210e = { 76 7c [2] 44 5e [2] 42 6b [2] 6c 6b [2] 53 77 }

  condition:
    any of them
}