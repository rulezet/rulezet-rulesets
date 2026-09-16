rule TTP_XOR_WriteProcessMemory_3ffb {
  strings:
    $key_3ffb = { 68 89 [2] 5a ab [2] 5c 9e [2] 72 9e [2] 4d 82 }

  condition:
    any of them
}