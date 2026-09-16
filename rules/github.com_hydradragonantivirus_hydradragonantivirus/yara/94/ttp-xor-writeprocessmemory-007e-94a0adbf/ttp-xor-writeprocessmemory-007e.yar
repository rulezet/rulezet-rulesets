rule TTP_XOR_WriteProcessMemory_007e {
  strings:
    $key_007e = { 57 0c [2] 65 2e [2] 63 1b [2] 4d 1b [2] 72 07 }

  condition:
    any of them
}