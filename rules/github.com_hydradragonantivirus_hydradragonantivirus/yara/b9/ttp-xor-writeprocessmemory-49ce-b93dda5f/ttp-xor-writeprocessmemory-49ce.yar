rule TTP_XOR_WriteProcessMemory_49ce {
  strings:
    $key_49ce = { 1e bc [2] 2c 9e [2] 2a ab [2] 04 ab [2] 3b b7 }

  condition:
    any of them
}