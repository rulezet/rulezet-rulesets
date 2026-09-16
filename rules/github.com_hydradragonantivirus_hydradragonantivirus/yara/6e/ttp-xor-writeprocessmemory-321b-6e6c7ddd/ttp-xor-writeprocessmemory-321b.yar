rule TTP_XOR_WriteProcessMemory_321b {
  strings:
    $key_321b = { 65 69 [2] 57 4b [2] 51 7e [2] 7f 7e [2] 40 62 }

  condition:
    any of them
}