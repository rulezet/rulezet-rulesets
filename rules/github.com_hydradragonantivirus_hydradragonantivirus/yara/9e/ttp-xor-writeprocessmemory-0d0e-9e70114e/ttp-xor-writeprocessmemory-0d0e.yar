rule TTP_XOR_WriteProcessMemory_0d0e {
  strings:
    $key_0d0e = { 5a 7c [2] 68 5e [2] 6e 6b [2] 40 6b [2] 7f 77 }

  condition:
    any of them
}