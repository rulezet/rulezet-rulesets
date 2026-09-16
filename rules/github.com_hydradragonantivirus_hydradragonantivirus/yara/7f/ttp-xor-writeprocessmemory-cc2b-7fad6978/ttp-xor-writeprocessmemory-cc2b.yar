rule TTP_XOR_WriteProcessMemory_cc2b {
  strings:
    $key_cc2b = { 9b 59 [2] a9 7b [2] af 4e [2] 81 4e [2] be 52 }

  condition:
    any of them
}