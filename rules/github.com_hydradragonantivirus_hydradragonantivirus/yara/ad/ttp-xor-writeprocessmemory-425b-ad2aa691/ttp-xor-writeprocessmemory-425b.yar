rule TTP_XOR_WriteProcessMemory_425b {
  strings:
    $key_425b = { 15 29 [2] 27 0b [2] 21 3e [2] 0f 3e [2] 30 22 }

  condition:
    any of them
}