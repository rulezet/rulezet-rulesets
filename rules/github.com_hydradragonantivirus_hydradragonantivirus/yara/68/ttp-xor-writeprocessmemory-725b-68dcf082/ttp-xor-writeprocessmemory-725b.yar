rule TTP_XOR_WriteProcessMemory_725b {
  strings:
    $key_725b = { 25 29 [2] 17 0b [2] 11 3e [2] 3f 3e [2] 00 22 }

  condition:
    any of them
}