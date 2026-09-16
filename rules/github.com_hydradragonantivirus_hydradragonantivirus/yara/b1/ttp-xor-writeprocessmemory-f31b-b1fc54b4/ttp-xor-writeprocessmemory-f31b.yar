rule TTP_XOR_WriteProcessMemory_f31b {
  strings:
    $key_f31b = { a4 69 [2] 96 4b [2] 90 7e [2] be 7e [2] 81 62 }

  condition:
    any of them
}