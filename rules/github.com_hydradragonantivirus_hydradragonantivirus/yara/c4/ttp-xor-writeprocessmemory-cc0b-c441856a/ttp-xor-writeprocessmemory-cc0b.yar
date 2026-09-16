rule TTP_XOR_WriteProcessMemory_cc0b {
  strings:
    $key_cc0b = { 9b 79 [2] a9 5b [2] af 6e [2] 81 6e [2] be 72 }

  condition:
    any of them
}