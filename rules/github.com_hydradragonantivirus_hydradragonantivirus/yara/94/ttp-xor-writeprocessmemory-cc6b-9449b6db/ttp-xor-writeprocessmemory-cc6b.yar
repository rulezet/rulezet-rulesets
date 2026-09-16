rule TTP_XOR_WriteProcessMemory_cc6b {
  strings:
    $key_cc6b = { 9b 19 [2] a9 3b [2] af 0e [2] 81 0e [2] be 12 }

  condition:
    any of them
}