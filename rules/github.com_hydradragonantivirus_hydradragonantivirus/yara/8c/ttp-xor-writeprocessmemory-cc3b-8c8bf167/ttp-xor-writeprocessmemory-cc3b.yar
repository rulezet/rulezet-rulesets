rule TTP_XOR_WriteProcessMemory_cc3b {
  strings:
    $key_cc3b = { 9b 49 [2] a9 6b [2] af 5e [2] 81 5e [2] be 42 }

  condition:
    any of them
}