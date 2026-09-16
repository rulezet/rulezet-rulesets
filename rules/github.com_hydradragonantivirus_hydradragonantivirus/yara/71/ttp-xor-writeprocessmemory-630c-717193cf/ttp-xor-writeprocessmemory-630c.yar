rule TTP_XOR_WriteProcessMemory_630c {
  strings:
    $key_630c = { 34 7e [2] 06 5c [2] 00 69 [2] 2e 69 [2] 11 75 }

  condition:
    any of them
}