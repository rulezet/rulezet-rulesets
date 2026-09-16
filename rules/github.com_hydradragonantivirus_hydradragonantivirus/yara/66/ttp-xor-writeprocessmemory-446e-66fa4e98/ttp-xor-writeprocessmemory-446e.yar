rule TTP_XOR_WriteProcessMemory_446e {
  strings:
    $key_446e = { 13 1c [2] 21 3e [2] 27 0b [2] 09 0b [2] 36 17 }

  condition:
    any of them
}