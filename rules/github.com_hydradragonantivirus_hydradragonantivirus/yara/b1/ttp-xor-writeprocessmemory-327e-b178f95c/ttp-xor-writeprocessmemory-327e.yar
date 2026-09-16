rule TTP_XOR_WriteProcessMemory_327e {
  strings:
    $key_327e = { 65 0c [2] 57 2e [2] 51 1b [2] 7f 1b [2] 40 07 }

  condition:
    any of them
}