rule TTP_XOR_WriteProcessMemory_630e {
  strings:
    $key_630e = { 34 7c [2] 06 5e [2] 00 6b [2] 2e 6b [2] 11 77 }

  condition:
    any of them
}